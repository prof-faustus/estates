/**
 * @estates/wallet — real BSV wallet (built on the official @bsv/sdk).
 *
 * Bridges ESTATES to the live chain: derive a real address, build + sign
 * (BIP-143) real P2PKH transactions, and broadcast them — regtest via a node's
 * JSON-RPC, testnet/mainnet via WhatsOnChain. MAINNET broadcasts are real value
 * and are refused unless explicitly confirmed (a money guard).
 */
import { PrivateKey, P2PKH, Transaction } from '@bsv/sdk';

export type Network = 'mainnet' | 'testnet' | 'regtest';

export interface Utxo {
  readonly sourceTxHex: string;  // raw hex of the tx that created this output
  readonly vout: number;
  readonly satoshis: number;
}
export interface PayTo { readonly address: string; readonly satoshis: number; }

export class Wallet {
  readonly key: PrivateKey;
  readonly network: Network;
  constructor(key: PrivateKey, network: Network) { this.key = key; this.network = network; }

  static random(network: Network): Wallet { return new Wallet(PrivateKey.fromRandom(), network); }
  static fromWif(wif: string, network: Network): Wallet { return new Wallet(PrivateKey.fromWif(wif), network); }

  /** This wallet's P2PKH address (mainnet vs test/regtest version byte). */
  get address(): string {
    return this.key.toAddress(this.network === 'mainnet' ? 'mainnet' : 'testnet').toString();
  }
  get publicKeyHashHex(): string { return this.key.toPublicKey().toHash('hex') as string; }

  /**
   * Build + sign a real BSV tx spending `utxos` (P2PKH owned by this wallet) to
   * `outputs`, with change back to this wallet and a standard fee. Returns the
   * signed tx hex + txid.
   */
  async buildAndSign(utxos: readonly Utxo[], outputs: readonly PayTo[]): Promise<{ hex: string; txid: string }> {
    if (utxos.length === 0) throw new Error('buildAndSign: no inputs');
    const tx = new Transaction();
    const unlock = new P2PKH().unlock(this.key);
    for (const u of utxos) {
      tx.addInput({
        sourceTransaction: Transaction.fromHex(u.sourceTxHex),
        sourceOutputIndex: u.vout,
        unlockingScriptTemplate: unlock,
      });
    }
    for (const o of outputs) {
      tx.addOutput({ lockingScript: new P2PKH().lock(o.address), satoshis: o.satoshis });
    }
    // change back to us
    tx.addOutput({ lockingScript: new P2PKH().lock(this.address), change: true });
    await tx.fee();
    await tx.sign();
    return { hex: tx.toHex(), txid: tx.id('hex') as string };
  }

  private woc(): 'main' | 'test' {
    if (this.network === 'regtest') throw new Error('balance/UTXOs/send over WhatsOnChain need testnet or mainnet');
    return this.network === 'mainnet' ? 'main' : 'test';
  }

  /** Confirmed + unconfirmed balance (sats) of this wallet, from WhatsOnChain. */
  async getBalance(): Promise<number> {
    const r = await fetch(`https://api.whatsonchain.com/v1/bsv/${this.woc()}/address/${this.address}/balance`);
    const j = (await r.json()) as { confirmed: number; unconfirmed: number };
    return (j.confirmed || 0) + (j.unconfirmed || 0);
  }

  /** Spendable UTXOs of this wallet (with each source tx's raw hex), from WhatsOnChain. */
  async fetchUtxos(): Promise<Utxo[]> {
    const net = this.woc();
    const r = await fetch(`https://api.whatsonchain.com/v1/bsv/${net}/address/${this.address}/unspent`);
    const us = (await r.json()) as { tx_hash: string; tx_pos: number; value: number }[];
    const out: Utxo[] = [];
    for (const u of us) {
      const raw = (await (await fetch(`https://api.whatsonchain.com/v1/bsv/${net}/tx/${u.tx_hash}/hex`)).text()).trim();
      out.push({ sourceTxHex: raw, vout: u.tx_pos, satoshis: u.value });
    }
    return out;
  }

  /**
   * SEND/spend: gather this wallet's UTXOs, pay `satoshis` to `toAddress` (change
   * back to you), sign, and broadcast. The CALLER (a human clicking Send) passes
   * `confirm: true`; mainnet additionally requires it as the money guard.
   */
  async send(toAddress: string, satoshis: number, confirm = false): Promise<{ txid: string }> {
    const utxos = await this.fetchUtxos();
    if (utxos.length === 0) throw new Error('no spendable funds — receive some first');
    const { hex } = await this.buildAndSign(utxos, [{ address: toAddress, satoshis }]);
    return this.broadcast(hex, { confirmRealValue: confirm });
  }

  /**
   * Broadcast a signed tx. regtest → the node's JSON-RPC `sendrawtransaction`;
   * testnet → WhatsOnChain; mainnet → WhatsOnChain ONLY if `confirmRealValue`.
   */
  async broadcast(hex: string, opts: { rpcUrl?: string; rpcUser?: string; rpcPass?: string; confirmRealValue?: boolean } = {}): Promise<{ txid: string }> {
    if (this.network === 'regtest') {
      if (!opts.rpcUrl) throw new Error('regtest broadcast needs rpcUrl');
      return rpcBroadcast(hex, opts.rpcUrl, opts.rpcUser ?? '', opts.rpcPass ?? '');
    }
    if (this.network === 'mainnet' && !opts.confirmRealValue) {
      throw new Error('refusing mainnet broadcast (real value) without confirmRealValue:true');
    }
    return wocBroadcast(hex, this.network === 'mainnet' ? 'main' : 'test');
  }
}

/** Broadcast to a regtest/local BSV node via JSON-RPC sendrawtransaction. */
export async function rpcBroadcast(hex: string, rpcUrl: string, user: string, pass: string): Promise<{ txid: string }> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Basic ' + Buffer.from(`${user}:${pass}`).toString('base64') },
    body: JSON.stringify({ jsonrpc: '1.0', id: 'estates', method: 'sendrawtransaction', params: [hex] }),
  });
  const j = (await res.json()) as { result?: string; error?: { message: string } };
  if (j.error) throw new Error(`rpc sendrawtransaction: ${j.error.message}`);
  return { txid: j.result! };
}

/** Broadcast a signed tx to WhatsOnChain (testnet `test` / mainnet `main`). */
export async function wocBroadcast(hex: string, net: 'main' | 'test'): Promise<{ txid: string }> {
  const res = await fetch(`https://api.whatsonchain.com/v1/bsv/${net}/tx/raw`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ txhex: hex }),
  });
  const body = (await res.text()).replace(/^"|"$/g, '').trim();
  if (!/^[0-9a-f]{64}$/.test(body)) throw new Error(`WhatsOnChain broadcast failed: ${body}`);
  return { txid: body };
}

/** Re-export the SDK primitives ESTATES uses, so callers need one dependency. */
export { PrivateKey, P2PKH, Transaction } from '@bsv/sdk';
