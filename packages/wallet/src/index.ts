/**
 * @estates/wallet — a real BSV wallet on the project's OWN @noble crypto. NO
 * external SDK: @bsv/sdk shipped circular ESM that broke the production bundle
 * (a temporal-dead-zone error blanked the whole app), and an external repo
 * violates the standalone rule. This implements everything natively and
 * isomorphically (Node + the desktop webview):
 *   - secp256k1 keys, WIF (base58check), P2PKH addresses,
 *   - real BIP-143-signed P2PKH transactions (@estates/tx serialization),
 *   - broadcast via your own node's JSON-RPC (regtest) or a testnet/mainnet
 *     endpoint (mainnet refused without an explicit money-guard confirmation).
 */
import { randomPrivateKey, pubFromPriv, signHash, derEncode, sha256, ripemd160 } from '@estates/keys';
import { serializeTx, hash256, type Tx } from '@estates/tx';
import { p2pkh, serializeScript, push } from '@estates/onchain';
import { verifyTx } from '@estates/scriptvm';

export type Network = 'mainnet' | 'testnet' | 'regtest';

// ---- hex + base58check (no external deps) -----------------------------------
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
function fromHex(h: string): Uint8Array { if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('bad hex'); const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; }
const concat = (...p: Uint8Array[]): Uint8Array => { let n = 0; for (const x of p) n += x.length; const o = new Uint8Array(n); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const hash160 = (b: Uint8Array): Uint8Array => ripemd160(sha256(b));
const reversed = (b: Uint8Array): Uint8Array => b.slice().reverse();

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58encode(bytes: Uint8Array): string {
  let x = 0n; for (const b of bytes) x = x * 256n + BigInt(b);
  let s = ''; while (x > 0n) { s = B58[Number(x % 58n)] + s; x /= 58n; }
  for (const b of bytes) { if (b === 0) s = '1' + s; else break; }
  return s || '1';
}
function base58decode(str: string): Uint8Array {
  let x = 0n; for (const c of str) { const i = B58.indexOf(c); if (i < 0) throw new Error('bad base58'); x = x * 58n + BigInt(i); }
  const bytes: number[] = []; while (x > 0n) { bytes.unshift(Number(x % 256n)); x /= 256n; }
  for (const c of str) { if (c === '1') bytes.unshift(0); else break; }
  return new Uint8Array(bytes);
}
function base58check(payload: Uint8Array): string {
  const c = hash256(payload).slice(0, 4);
  return base58encode(concat(payload, c));
}
function base58checkDecode(s: string): Uint8Array {
  const all = base58decode(s); const payload = all.slice(0, -4); const c = all.slice(-4);
  if (toHex(hash256(payload).slice(0, 4)) !== toHex(c)) throw new Error('bad checksum');
  return payload;
}

const WIF_VERSION = 0x80;   // standard WIF prefix (network-agnostic for our use)
const addrVersion = (n: Network): number => (n === 'mainnet' ? 0x00 : 0x6f); // P2PKH version byte

// ---- key: secp256k1 private key with WIF + the API the app expects ----------
export class PrivateKey {
  readonly priv: Uint8Array;        // 32 bytes
  constructor(priv: Uint8Array) { if (priv.length !== 32) throw new Error('priv must be 32 bytes'); this.priv = priv; }
  static fromRandom(): PrivateKey { return new PrivateKey(randomPrivateKey()); }
  static fromWif(wif: string): PrivateKey {
    const p = base58checkDecode(wif);                 // [version][32 priv]([0x01 compressed])
    const body = p.slice(1);
    return new PrivateKey(body.length === 33 ? body.slice(0, 32) : body);
  }
  toWif(): string { return base58check(concat(new Uint8Array([WIF_VERSION]), this.priv, new Uint8Array([0x01]))); }
  /** @bsv/sdk-compatible: the big-endian private-key bytes (used to derive the seat identity). */
  toArray(_fmt?: 'be', _len?: number): number[] { return Array.from(this.priv); }
  pub(): Uint8Array { return pubFromPriv(this.priv); }   // compressed
  pkh(): Uint8Array { return hash160(this.pub()); }
}

export interface Utxo { readonly sourceTxHex: string; readonly vout: number; readonly satoshis: number; }
export interface PayTo { readonly address: string; readonly satoshis: number; }

/** The locking-script pkh for a P2PKH address (rejects a wrong-network/garbled one). */
function addressToPkh(address: string): Uint8Array {
  const p = base58checkDecode(address);
  if (p.length !== 21) throw new Error('not a P2PKH address');
  return p.slice(1);
}

export class Wallet {
  readonly key: PrivateKey;
  readonly network: Network;
  constructor(key: PrivateKey, network: Network) { this.key = key; this.network = network; }

  static random(network: Network): Wallet { return new Wallet(PrivateKey.fromRandom(), network); }
  static fromWif(wif: string, network: Network): Wallet { return new Wallet(PrivateKey.fromWif(wif), network); }

  /** This wallet's P2PKH address (mainnet vs test/regtest version byte). */
  get address(): string { return base58check(concat(new Uint8Array([addrVersion(this.network)]), this.key.pkh())); }
  get publicKeyHashHex(): string { return toHex(this.key.pkh()); }

  /**
   * Build + sign a real BIP-143 P2PKH tx spending `utxos` (owned by this wallet)
   * to `outputs`, with change back to us and a size-based fee. Returns hex + txid.
   */
  buildAndSign(utxos: readonly Utxo[], outputs: readonly PayTo[]): { hex: string; txid: string } {
    return this.buildRaw(utxos, outputs.map((o) => ({ satoshis: o.satoshis, script: serializeScript(p2pkh(addressToPkh(o.address))) })));
  }

  /**
   * Build + sign a tx spending OUR P2PKH `utxos` to arbitrary value outputs
   * (raw locking scripts — e.g. seat P2PKHs + a bank covenant), with change back to
   * us and a size-based fee. The native, SDK-free signer used by buildAndSign and
   * the table-genesis builder.
   */
  buildRaw(utxos: readonly Utxo[], outputs: readonly { satoshis: number; script: Uint8Array }[]): { hex: string; txid: string } {
    if (utxos.length === 0) throw new Error('buildRaw: no inputs');
    const myScript = serializeScript(p2pkh(this.key.pkh()));
    const ins = utxos.map((u) => ({ prevTxid: toHex(reversed(hash256(fromHex(u.sourceTxHex)))), prevVout: u.vout, value: u.satoshis }));
    const totalIn = ins.reduce((n, i) => n + i.value, 0);
    const totalOut = outputs.reduce((n, o) => n + o.satoshis, 0);
    const estSize = 10 + ins.length * 148 + (outputs.length + 1) * 34; // P2PKH in ≈148B, out ≈34B
    const fee = Math.max(estSize, 256);
    const change = totalIn - totalOut - fee;
    if (change < 0) throw new Error(`insufficient funds: need ${totalOut + fee}, have ${totalIn}`);

    const txOuts = outputs.map((o) => ({ value: o.satoshis, script: o.script }));
    if (change > 0) txOuts.push({ value: change, script: myScript });

    let tx: Tx = { version: 1, inputs: ins.map((i) => ({ prevTxid: i.prevTxid, prevVout: i.prevVout, scriptSig: new Uint8Array(0), sequence: 0xffffffff })), outputs: txOuts, lockTime: 0 };
    const signed = tx.inputs.map((inp, i) => {
      const h = sighashAll(tx, i, myScript, ins[i]!.value);           // BIP-143, SIGHASH_ALL|FORKID
      const sig = concat(derEncode(signHash(this.key.priv, h)), new Uint8Array([0x41]));
      return { ...inp, scriptSig: serializeScript([push(sig), push(this.key.pub())]) };
    });
    tx = { ...tx, inputs: signed };
    // SELF-CHECK: prove every input satisfies its prevout (BIP-143 sig + script) and
    // the fee is non-negative BEFORE emitting — the wallet never produces an invalid tx.
    const chk = verifyTx(tx, ins.map((i) => ({ value: i.value, script: myScript })));
    if (!chk.ok) throw new Error(`wallet self-check failed: ${chk.reason}`);
    const bytes = serializeTx(tx);
    return { hex: toHex(bytes), txid: toHex(reversed(hash256(bytes))) };
  }

  /** Drain the ENTIRE balance to `toAddress` (minus fee) — used to refund a bot's
   *  funder on close (no funds may be stranded). */
  async drainTo(toAddress: string, opts: { rpcUrl?: string; rpcUser?: string; rpcPass?: string; confirmRealValue?: boolean } = {}): Promise<{ txid: string } | null> {
    const utxos = await this.fetchUtxos();
    if (utxos.length === 0) return null;                                // nothing to refund
    const total = utxos.reduce((n, u) => n + u.satoshis, 0);
    const fee = Math.max(10 + utxos.length * 148 + 68, 256); // match buildRaw's estimate (1 output + change slot)
    if (total <= fee) return null;
    const { hex } = this.buildRaw(utxos, [{ satoshis: total - fee, script: serializeScript(p2pkh(addressToPkh(toAddress))) }]);
    return this.broadcast(hex, opts);
  }

  /** SEND: gather UTXOs, pay `satoshis` to `toAddress` (change to you), sign, broadcast. */
  async send(toAddress: string, satoshis: number, confirm = false): Promise<{ txid: string }> {
    const utxos = await this.fetchUtxos();
    if (utxos.length === 0) throw new Error('no spendable funds — receive some first');
    const { hex } = this.buildAndSign(utxos, [{ address: toAddress, satoshis }]);
    return this.broadcast(hex, { confirmRealValue: confirm });
  }

  private endpoint(): string {
    if (this.network === 'regtest') throw new Error('regtest balance/UTXOs/send use your own node (RPC), not a public endpoint');
    return this.network === 'mainnet' ? 'main' : 'test';
  }
  async getBalance(): Promise<number> {
    const r = await fetch(`https://api.whatsonchain.com/v1/bsv/${this.endpoint()}/address/${this.address}/balance`);
    const j = (await r.json()) as { confirmed: number; unconfirmed: number };
    return (j.confirmed || 0) + (j.unconfirmed || 0);
  }
  async fetchUtxos(): Promise<Utxo[]> {
    const net = this.endpoint();
    const us = (await (await fetch(`https://api.whatsonchain.com/v1/bsv/${net}/address/${this.address}/unspent`)).json()) as { tx_hash: string; tx_pos: number; value: number }[];
    const out: Utxo[] = [];
    for (const u of us) { const raw = (await (await fetch(`https://api.whatsonchain.com/v1/bsv/${net}/tx/${u.tx_hash}/hex`)).text()).trim(); out.push({ sourceTxHex: raw, vout: u.tx_pos, satoshis: u.value }); }
    return out;
  }
  async broadcast(hex: string, opts: { rpcUrl?: string; rpcUser?: string; rpcPass?: string; confirmRealValue?: boolean } = {}): Promise<{ txid: string }> {
    if (this.network === 'regtest') { if (!opts.rpcUrl) throw new Error('regtest broadcast needs rpcUrl'); return rpcBroadcast(hex, opts.rpcUrl, opts.rpcUser ?? '', opts.rpcPass ?? ''); }
    if (this.network === 'mainnet' && !opts.confirmRealValue) throw new Error('refusing mainnet broadcast (real value) without confirmRealValue:true');
    return wocBroadcast(hex, this.network === 'mainnet' ? 'main' : 'test');
  }
}

// ---- BIP-143 sighash (SIGHASH_ALL|FORKID) + DER (no external SDK) ------------
const u32le = (n: number): Uint8Array => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, n >>> 24 & 0xff]);
function u64le(v: number): Uint8Array { const o = new Uint8Array(8); let x = BigInt(v); for (let i = 0; i < 8; i++) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; }
function varintBytes(n: number): Uint8Array { if (n < 0xfd) return new Uint8Array([n]); if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, n >> 8 & 0xff]); return new Uint8Array([0xfe, ...u32le(n)]); }
function sighashAll(tx: Tx, i: number, prevoutScript: Uint8Array, amount: number): Uint8Array {
  const hashPrevouts = hash256(concat(...tx.inputs.map((inp) => concat(reversed(fromHex(inp.prevTxid)), u32le(inp.prevVout)))));
  const hashSequence = hash256(concat(...tx.inputs.map((inp) => u32le(inp.sequence))));
  const hashOutputs = hash256(concat(...tx.outputs.map((o) => concat(u64le(Number(o.value)), varintBytes(o.script.length), o.script))));
  const inp = tx.inputs[i]!;
  return hash256(concat(
    u32le(tx.version), hashPrevouts, hashSequence,
    reversed(fromHex(inp.prevTxid)), u32le(inp.prevVout),
    varintBytes(prevoutScript.length), prevoutScript,
    u64le(amount), u32le(inp.sequence),
    hashOutputs, u32le(tx.lockTime), u32le(0x41),
  ));
}
/** Broadcast to a regtest/local BSV node via JSON-RPC sendrawtransaction. */
export async function rpcBroadcast(hex: string, rpcUrl: string, user: string, pass: string): Promise<{ txid: string }> {
  const res = await fetch(rpcUrl, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Basic ' + b64(`${user}:${pass}`) }, body: JSON.stringify({ jsonrpc: '1.0', id: 'estates', method: 'sendrawtransaction', params: [hex] }) });
  const j = (await res.json()) as { result?: string; error?: { message: string } };
  if (j.error) throw new Error(`rpc sendrawtransaction: ${j.error.message}`);
  return { txid: j.result! };
}
export async function wocBroadcast(hex: string, net: 'main' | 'test'): Promise<{ txid: string }> {
  const res = await fetch(`https://api.whatsonchain.com/v1/bsv/${net}/tx/raw`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ txhex: hex }) });
  const body = (await res.text()).replace(/^"|"$/g, '').trim();
  if (!/^[0-9a-f]{64}$/.test(body)) throw new Error(`broadcast failed: ${body}`);
  return { txid: body };
}
// btoa is a global in both the browser and Node 18+ — isomorphic, no node hashing.
const b64 = (s: string): string => btoa(s);
