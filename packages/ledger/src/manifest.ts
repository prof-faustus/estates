/**
 * Genesis KEY MANIFEST (red-team #2): a genesis transaction must not pay arbitrary
 * raw scripts. Every spendable output is backed by a manifest entry proving the
 * output key is FRESH, ECDH-derived, game-scoped, purpose-bound, non-reused, and
 * recoverable by a known identity — or, for the bank, locked under the covenant.
 *
 * Each P2PKH entry carries the deriver's stable identity, the one-use derived
 * spend key, the pkh, the derivation context, and a CERTIFICATION signature by the
 * identity's signing key over the entry. `verifyGenesisManifest` rejects any
 * genesis output that lacks a valid entry — no raw, reusable hashes.
 */
import type { Tx } from '@estates/tx';
import { p2pkh, serializeScript } from '@estates/onchain';
import { pkhOf, deriveSelf, spendContext, type KeyPair } from '@estates/keys';
import { signData, verifyData, signingKeyFromMaster } from '@estates/channel';
import { covenantOutput, rulesHash } from '@estates/bank';

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
function fromHex(h: string): Uint8Array {
  if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('bad hex');
  const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}
const endsWith = (a: Uint8Array, suf: Uint8Array): boolean => {
  if (suf.length > a.length) return false;
  for (let i = 0; i < suf.length; i++) if (a[a.length - suf.length + i] !== suf[i]) return false;
  return true;
};

export interface GenesisKeyEntry {
  readonly outputIndex: number;
  readonly purpose: string;                 // 'cursor' | 'seat-fund' | 'mint' | …
  readonly custody: 'p2pkh' | 'covenant';
  // p2pkh (spendable) entries:
  readonly stableIdentityPub?: string;      // the deriver's master (wallet) pub
  readonly signPub?: string;                // Ed25519 signing pub (derived from master)
  readonly derivedSpendPub?: string;        // the one-use child pub for THIS output
  readonly pkh?: string;                    // pkhOf(derivedSpendPub)
  readonly derivationContext?: string;      // the BRC-42 spendContext invoice
  readonly certSig?: string;                // Ed25519 sig by signPub over the entry
  // covenant (bank reserve / bank-held NFT) entries:
  readonly rulesHashHex?: string;
}
export type GenesisManifest = readonly GenesisKeyEntry[];

/** Canonical bytes of an entry (everything but the signature) — what certSig covers. */
function entryBytes(gameId: string, e: GenesisKeyEntry): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    k: 'estates-genesis-key-v1', gameId, outputIndex: e.outputIndex, purpose: e.purpose, custody: e.custody,
    stableIdentityPub: e.stableIdentityPub ?? null, signPub: e.signPub ?? null,
    derivedSpendPub: e.derivedSpendPub ?? null, pkh: e.pkh ?? null,
    derivationContext: e.derivationContext ?? null, rulesHashHex: e.rulesHashHex ?? null,
  }));
}

export interface ManifestCheck { readonly ok: boolean; readonly reason: string }

/**
 * Verify a genesis manifest against the actual tx: EVERY output is accounted for,
 * each p2pkh output is a certified fresh one-use derived key (recoverable by its
 * identity), each covenant output is the self-enforcing reserve script, and NO
 * spend key (pkh / derived pub) is reused across outputs.
 */
export function verifyGenesisManifest(tx: Tx, manifest: GenesisManifest, gameId: string): ManifestCheck {
  if (manifest.length !== tx.outputs.length) return { ok: false, reason: `manifest covers ${manifest.length} of ${tx.outputs.length} outputs` };
  const seenPkh = new Set<string>();
  const seenPub = new Set<string>();
  for (let i = 0; i < tx.outputs.length; i++) {
    const e = manifest.find((m) => m.outputIndex === i);
    if (!e) return { ok: false, reason: `output ${i} has no manifest entry (raw script forbidden)` };
    const out = tx.outputs[i]!;

    if (e.custody === 'covenant') {
      const rh = e.rulesHashHex ? fromHex(e.rulesHashHex) : rulesHash();
      if (toHex(out.script) !== toHex(covenantOutput(Number(out.value), rh).script)) return { ok: false, reason: `output ${i} is not the covenant reserve script` };
      continue;
    }

    // p2pkh: a fresh, certified, recoverable one-use key
    if (!e.derivedSpendPub || !e.pkh || !e.signPub || !e.stableIdentityPub || !e.derivationContext || !e.certSig) {
      return { ok: false, reason: `output ${i} p2pkh entry is missing derivation evidence` };
    }
    let dPub: Uint8Array, pkh: Uint8Array, signPub: Uint8Array, sig: Uint8Array;
    try { dPub = fromHex(e.derivedSpendPub); pkh = fromHex(e.pkh); signPub = fromHex(e.signPub); sig = fromHex(e.certSig); } catch { return { ok: false, reason: `output ${i} has malformed hex` }; }
    if (e.derivedSpendPub === e.stableIdentityPub) return { ok: false, reason: `output ${i} reuses the identity key as a spend key (not fresh)` };
    if (toHex(pkhOf(dPub)) !== e.pkh) return { ok: false, reason: `output ${i} pkh ≠ hash160(derivedSpendPub)` };
    if (!endsWith(out.script, serializeScript(p2pkh(pkh)))) return { ok: false, reason: `output ${i} script does not pay the manifested pkh` };
    if (!verifyData(entryBytes(gameId, e), sig, signPub)) return { ok: false, reason: `output ${i} certification signature is invalid` };
    if (seenPkh.has(e.pkh) || seenPub.has(e.derivedSpendPub)) return { ok: false, reason: `output ${i} reuses a one-use key (already used in this genesis)` };
    seenPkh.add(e.pkh); seenPub.add(e.derivedSpendPub);
  }
  return { ok: true, reason: `verified ${manifest.length} genesis outputs: fresh ECDH-derived/covenant custody, no reuse` };
}

/** Derive + CERTIFY a p2pkh genesis output key for `master` at (purpose, outputIndex). */
export function certifyGenesisKey(master: KeyPair, gameId: string, network: string, purpose: string, outputIndex: number): GenesisKeyEntry {
  const derivationContext = spendContext({ gameId, network, purpose, role: outputIndex, turnIndex: 0, outputIndex, asset: 'genesis' });
  const child = deriveSelf(master, derivationContext);
  const signKey = signingKeyFromMaster(master.priv);
  const base: GenesisKeyEntry = {
    outputIndex, purpose, custody: 'p2pkh',
    stableIdentityPub: toHex(master.pub), signPub: toHex(signKey.pub),
    derivedSpendPub: toHex(child.pub), pkh: toHex(pkhOf(child.pub)), derivationContext,
  };
  return { ...base, certSig: toHex(signData(entryBytes(gameId, base), signKey.priv)) };
}

/** A covenant manifest entry (bank reserve / bank-held NFT — no spend key). */
export function covenantGenesisEntry(outputIndex: number, purpose: string, rh: Uint8Array = rulesHash()): GenesisKeyEntry {
  return { outputIndex, purpose, custody: 'covenant', rulesHashHex: toHex(rh) };
}
