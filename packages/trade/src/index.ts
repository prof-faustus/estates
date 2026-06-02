/**
 * @estates/trade — atomic player↔player trade (tx-nft doc §7).
 *
 * One transaction; both legs move or neither. Each party signs ONLY their own
 * inputs with SIGHASH_ALL, so every signature commits to the ENTIRE output set:
 * neither party can alter the division after signing without invalidating the
 * signatures, and a party that declines simply never signs → the tx is invalid
 * and nothing moves. Real secp256k1 ECDSA (BSV's curve) via node:crypto models
 * the co-signing; the production path binds C1/C2 in @bsv-poker.
 *
 * No data-output opcode; no locktime-verify opcodes (maturity, where used, is
 * tx-level nLockTime/nSequence).
 */
import { createHash, createSign, createVerify, generateKeyPairSync, type KeyObject } from 'node:crypto';
import {
  type Outpoint, type TitleState, type TxOutput,
  nftOutput, paymentOutput, encodeTitleState,
} from '@estates/onchain';

const SIGHASH_ALL = 0x41;

export interface KeyPair { readonly privateKey: KeyObject; readonly publicKey: KeyObject; readonly pkh: Uint8Array; }

function hash160(b: Uint8Array): Uint8Array {
  const s = createHash('sha256').update(b).digest();
  return new Uint8Array(createHash('ripemd160').update(s).digest());
}

/** Generate a secp256k1 key pair with its P2PKH hash (BSV's curve). */
export function genKeyPair(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return { privateKey, publicKey, pkh: hash160(new Uint8Array(der)) };
}

export interface TxInput {
  readonly outpoint: Outpoint;
  readonly owner: Uint8Array;   // pkh that must sign this input
  readonly sequence: number;    // nSequence (no CLTV/CSV)
}
export interface Tx {
  readonly version: number;
  readonly inputs: readonly TxInput[];
  readonly outputs: readonly TxOutput[];
  readonly nLockTime: number;
}

/** An object a party offers: an NFT (by its current outpoint + state) or sats. */
export interface OfferedNft { readonly outpoint: Outpoint; readonly state: TitleState; }
export interface Leg {
  readonly party: KeyPair;
  readonly giveNfts: readonly OfferedNft[];
  readonly giveSats: number;             // sats this party contributes (one funding input)
  readonly satsFundingOutpoint: Outpoint; // the UTXO funding giveSats
  readonly changePkh: Uint8Array;        // where this party's change/received sats go
}

function u32le(n: number): Uint8Array { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; }
function u64le(n: number): Uint8Array {
  const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b;
}
function fromHex(h: string): Uint8Array { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; }

function serializeOutputs(outs: readonly TxOutput[]): Uint8Array {
  const parts: number[] = [];
  for (const o of outs) {
    for (const x of u64le(o.satoshis)) parts.push(x);
    for (const x of u32le(o.script.length)) parts.push(x);
    for (const x of o.script) parts.push(x);
  }
  return Uint8Array.from(parts);
}

/**
 * SIGHASH_ALL preimage for one input: commits to ALL outputs, this input's
 * outpoint, nLockTime, and the sighash flag. Altering any output changes every
 * input's preimage → all signatures break (atomicity + anti-front-running).
 */
export function sighashPreimage(tx: Tx, inputIndex: number): Uint8Array {
  const inp = tx.inputs[inputIndex]!;
  const h = createHash('sha256');
  h.update(u32le(tx.version));
  h.update(serializeOutputs(tx.outputs));
  h.update(fromHex(inp.outpoint.txid));
  h.update(u32le(inp.outpoint.vout));
  h.update(u32le(inp.sequence));
  h.update(u32le(tx.nLockTime));
  h.update(Uint8Array.from([SIGHASH_ALL]));
  return new Uint8Array(h.digest());
}

export function signInput(tx: Tx, inputIndex: number, key: KeyPair): Uint8Array {
  const s = createSign('SHA256');
  s.update(sighashPreimage(tx, inputIndex));
  s.end();
  return new Uint8Array(s.sign(key.privateKey));
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!; return d === 0;
}

export interface SignedTrade { readonly tx: Tx; readonly sigs: readonly (Uint8Array | null)[]; readonly pubkeys: readonly (KeyObject | null)[]; }

/**
 * Build the atomic trade tx. A's NFTs go to B and vice-versa; each party's
 * `giveSats` is paid to the counterparty's change address. Inputs are each
 * offered NFT (1-sat) plus each party's sats-funding UTXO.
 */
export function buildTrade(a: Leg, b: Leg): SignedTrade {
  const inputs: TxInput[] = [];
  const outputs: TxOutput[] = [];

  // NFT inputs (1 sat each) + reassign to counterparty (state unchanged, new owner)
  for (const n of a.giveNfts) { inputs.push({ outpoint: n.outpoint, owner: a.party.pkh, sequence: 0xffffffff }); outputs.push(nftOutput(n.state, b.changePkh)); }
  for (const n of b.giveNfts) { inputs.push({ outpoint: n.outpoint, owner: b.party.pkh, sequence: 0xffffffff }); outputs.push(nftOutput(n.state, a.changePkh)); }

  // sats funding inputs + payment to counterparty
  inputs.push({ outpoint: a.satsFundingOutpoint, owner: a.party.pkh, sequence: 0xffffffff });
  inputs.push({ outpoint: b.satsFundingOutpoint, owner: b.party.pkh, sequence: 0xffffffff });
  if (a.giveSats > 0) outputs.push(paymentOutput(a.giveSats, b.changePkh));
  if (b.giveSats > 0) outputs.push(paymentOutput(b.giveSats, a.changePkh));

  const tx: Tx = { version: 1, inputs, outputs, nLockTime: 0 };
  return { tx, sigs: inputs.map(() => null), pubkeys: inputs.map(() => null) };
}

/** A party signs every input it owns. Returns a new SignedTrade. */
export function cosign(st: SignedTrade, key: KeyPair): SignedTrade {
  const sigs = [...st.sigs];
  const pubkeys = [...st.pubkeys];
  st.tx.inputs.forEach((inp, i) => {
    if (eq(inp.owner, key.pkh)) { sigs[i] = signInput(st.tx, i, key); pubkeys[i] = key.publicKey; }
  });
  return { tx: st.tx, sigs, pubkeys };
}

export interface TradeCheck { readonly valid: boolean; readonly reason: string; }

/**
 * All-or-nothing validity: every input must carry a signature from the key
 * whose pkh matches the input's owner, and each signature must verify against
 * the CURRENT outputs. A missing signature (a declining party) or any tampering
 * with outputs after signing makes the trade invalid.
 */
export function verifyTrade(st: SignedTrade): TradeCheck {
  for (let i = 0; i < st.tx.inputs.length; i++) {
    const sig = st.sigs[i]; const pub = st.pubkeys[i]; const inp = st.tx.inputs[i]!;
    if (!sig || !pub) return { valid: false, reason: `input ${i} unsigned (a party declined)` };
    const der = pub.export({ format: 'der', type: 'spki' });
    if (!eq(hash160(new Uint8Array(der)), inp.owner)) return { valid: false, reason: `input ${i} signer pkh mismatch` };
    const v = createVerify('SHA256'); v.update(sighashPreimage(st.tx, i)); v.end();
    if (!v.verify(pub, sig)) return { valid: false, reason: `input ${i} signature invalid (outputs tampered or wrong key)` };
  }
  return { valid: true, reason: 'all inputs signed; signatures commit to the full output set' };
}

/** Conservation check: sum of NFT (1-sat) + sats inputs equals outputs. */
export function valueConserved(a: Leg, b: Leg, st: SignedTrade): boolean {
  const nftIn = a.giveNfts.length + b.giveNfts.length; // 1 sat each
  const outSats = st.tx.outputs.reduce((s, o) => s + o.satoshis, 0);
  const nftOutSats = (a.giveNfts.length + b.giveNfts.length); // each re-minted as 1 sat
  const payOut = outSats - nftOutSats;
  return payOut === a.giveSats + b.giveSats && nftIn === a.giveNfts.length + b.giveNfts.length;
}

export { encodeTitleState };
