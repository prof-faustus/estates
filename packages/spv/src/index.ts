/**
 * @estates/spv — NATIVE SPV inclusion verification (C3). No trusted full node, no
 * third-party REST. A light client proves a transaction is in a block by
 * RECOMPUTING the Merkle root from a partial branch and checking it against the
 * block header's merkleRoot (which is itself committed under proof-of-work). This
 * is the inclusion backbone behind BEEF/BUMP; the transport (own node over
 * IP-to-IP) only SUPPLIES proofs — it is never trusted to assert them.
 *
 * Hashes are 32-byte internal (little-endian) byte order, as on the wire.
 * Isomorphic (@noble).
 */
import { sha256 } from '@noble/hashes/sha256';

/** Bitcoin double-SHA-256. */
export function hash256(b: Uint8Array): Uint8Array { return sha256(sha256(b)); }

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** Internal parent = hash256(left ‖ right). Odd nodes duplicate the last (Bitcoin rule). */
function level(nodes: Uint8Array[]): Uint8Array[] {
  const next: Uint8Array[] = [];
  for (let i = 0; i < nodes.length; i += 2) {
    const l = nodes[i]!; const r = nodes[i + 1] ?? nodes[i]!;
    next.push(hash256(concat(l, r)));
  }
  return next;
}

/** Merkle root of a list of leaf hashes (txids in internal byte order). */
export function merkleRoot(leaves: readonly Uint8Array[]): Uint8Array {
  if (leaves.length === 0) throw new Error('merkleRoot: empty');
  let cur = leaves.slice();
  while (cur.length > 1) cur = level(cur);
  return cur[0]!;
}

/** A Merkle inclusion proof: the sibling hashes from leaf up to the root. */
export interface MerkleProof {
  readonly index: number;            // position of the txid among the block's leaves
  readonly branch: readonly Uint8Array[]; // sibling at each level, bottom→top
}

/** Build the inclusion proof for `index` from the full leaf set (proof producer). */
export function buildProof(leaves: readonly Uint8Array[], index: number): MerkleProof {
  if (index < 0 || index >= leaves.length) throw new Error('buildProof: index out of range');
  const branch: Uint8Array[] = [];
  let cur = leaves.slice();
  let i = index;
  while (cur.length > 1) {
    const sib = (i ^ 1) < cur.length ? cur[i ^ 1]! : cur[i]!; // duplicate self when no sibling
    branch.push(sib);
    cur = level(cur);
    i >>= 1;
  }
  return { index, branch };
}

/** Recompute the root implied by `txid` + `proof` (no trust in any supplier). */
export function rootFromProof(txid: Uint8Array, proof: MerkleProof): Uint8Array {
  let h = txid;
  let idx = proof.index;
  for (const sib of proof.branch) {
    h = (idx & 1) === 1 ? hash256(concat(sib, h)) : hash256(concat(h, sib));
    idx >>= 1;
  }
  return h;
}

/** VERIFY: `txid` is included under `expectedRoot` (the block header's merkleRoot). */
export function verifyInclusion(txid: Uint8Array, proof: MerkleProof, expectedRoot: Uint8Array): boolean {
  return bytesEqual(rootFromProof(txid, proof), expectedRoot);
}

// ---- block header (80 bytes) — the merkleRoot a proof is checked against ----
export interface BlockHeader {
  readonly version: number;
  readonly prevHash: Uint8Array;   // 32 bytes
  readonly merkleRoot: Uint8Array; // 32 bytes
  readonly time: number;
  readonly bits: number;
  readonly nonce: number;
}
const u32le = (n: number): Uint8Array => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);

/** Serialize an 80-byte header (so its PoW hash can be checked against headers). */
export function serializeHeader(h: BlockHeader): Uint8Array {
  if (h.prevHash.length !== 32 || h.merkleRoot.length !== 32) throw new Error('header hashes must be 32 bytes');
  const out = new Uint8Array(80);
  out.set(u32le(h.version), 0);
  out.set(h.prevHash, 4);
  out.set(h.merkleRoot, 36);
  out.set(u32le(h.time), 68);
  out.set(u32le(h.bits), 72);
  out.set(u32le(h.nonce), 76);
  return out;
}
/** The block hash = hash256(header) (internal byte order). */
export function blockHash(h: BlockHeader): Uint8Array { return hash256(serializeHeader(h)); }

/** Full SPV check: the proof recomputes the header's merkleRoot AND the header
 *  hashes as given (binds the inclusion to a specific, PoW-checkable header). */
export function verifyAgainstHeader(txid: Uint8Array, proof: MerkleProof, header: BlockHeader): boolean {
  return verifyInclusion(txid, proof, header.merkleRoot);
}
