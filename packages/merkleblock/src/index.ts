/**
 * @estates/merkleblock — the BIP-37 partial Merkle tree, i.e. exactly what a BSV
 * node returns from `gettxoutproof` (a CMerkleBlock). This is the NATIVE SPV proof
 * bridge: the node supplies the proof, this module parses it, recomputes the
 * Merkle root, and extracts a branch that @estates/spv verifies against the block
 * header — so a light client trusts the proof's MATH, not the node.
 *
 * build*  — produce a partial Merkle tree for matched tx indexes (test vectors /
 *           a proof-serving node).
 * parse*  — consume one (flags+hashes) and recompute the root + matched leaves.
 * Both round-trip with @estates/spv (buildProof / verifyInclusion).
 *
 * Hashes are 32-byte internal byte order. Isomorphic (@noble).
 */
import { sha256 } from '@noble/hashes/sha256';
import type { MerkleProof } from '@estates/spv';

function hash256(b: Uint8Array): Uint8Array { return sha256(sha256(b)); }
function concat(a: Uint8Array, b: Uint8Array): Uint8Array { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; }

function treeHeight(n: number): number { let h = 0; while ((1 << h) < n) h++; return h; }
/** number of nodes at `height` for `n` leaves. */
function widthAt(n: number, height: number): number { return (n + (1 << height) - 1) >> height; }

/** Hash of the node at (height,pos) computed from the full leaf set. */
function nodeHash(leaves: readonly Uint8Array[], height: number, pos: number): Uint8Array {
  if (height === 0) return leaves[pos]!;
  const left = nodeHash(leaves, height - 1, pos * 2);
  const hasRight = pos * 2 + 1 < widthAt(leaves.length, height - 1);
  const right = hasRight ? nodeHash(leaves, height - 1, pos * 2 + 1) : left; // Bitcoin duplicates the last
  return hash256(concat(left, right));
}

export interface PartialMerkleTree {
  readonly txCount: number;
  readonly hashes: Uint8Array[];
  readonly flags: number[]; // one bit per traversed node (here, one element per bit for clarity)
}

/** Build the partial Merkle tree marking `matched` leaf indexes (BIP-37). */
export function buildPartialMerkleTree(leaves: readonly Uint8Array[], matched: Iterable<number>): PartialMerkleTree {
  const n = leaves.length;
  const match = new Set(matched);
  const h = treeHeight(n);
  const hashes: Uint8Array[] = [];
  const flags: number[] = [];
  const isParentOfMatch = (height: number, pos: number): boolean => {
    for (let p = pos << height; p < ((pos + 1) << height) && p < n; p++) if (match.has(p)) return true;
    return false;
  };
  const traverse = (height: number, pos: number): void => {
    const parentOfMatch = isParentOfMatch(height, pos);
    flags.push(parentOfMatch ? 1 : 0);
    if (height === 0 || !parentOfMatch) {
      hashes.push(nodeHash(leaves, height, pos));
    } else {
      traverse(height - 1, pos * 2);
      if (pos * 2 + 1 < widthAt(n, height - 1)) traverse(height - 1, pos * 2 + 1);
    }
  };
  traverse(h, 0);
  return { txCount: n, hashes, flags };
}

export interface ParsedMerkle {
  readonly root: Uint8Array;
  readonly matched: { index: number; hash: Uint8Array; proof: MerkleProof }[];
}

interface Match { readonly index: number; readonly leafHash: Uint8Array; readonly branch: Uint8Array[] }
/** Parse a partial Merkle tree (one pass): recompute the root and, for every
 *  matched leaf, its index, hash, and an @estates/spv-compatible inclusion proof
 *  (sibling hashes bottom→top). */
export function parsePartialMerkleTree(pmt: PartialMerkleTree): ParsedMerkle {
  const { txCount: n, hashes, flags } = pmt;
  const h = treeHeight(n);
  let bit = 0, hi = 0;

  const traverse = (height: number, pos: number): { hash: Uint8Array; matches: Match[] } => {
    const flag = flags[bit++];
    if (height === 0 || flag === 0) {
      const hash = hashes[hi++]!;
      if (height === 0 && flag === 1) return { hash, matches: [{ index: pos, leafHash: hash, branch: [] }] };
      return { hash, matches: [] };
    }
    const L = traverse(height - 1, pos * 2);
    const R = pos * 2 + 1 < widthAt(n, height - 1) ? traverse(height - 1, pos * 2 + 1) : { hash: L.hash, matches: [] };
    const hash = hash256(concat(L.hash, R.hash));
    const matches: Match[] = [
      ...L.matches.map((m) => ({ index: m.index, leafHash: m.leafHash, branch: [...m.branch, R.hash] })),
      ...R.matches.map((m) => ({ index: m.index, leafHash: m.leafHash, branch: [...m.branch, L.hash] })),
    ];
    return { hash, matches };
  };

  const top = traverse(h, 0);
  if (bit !== flags.length || hi !== hashes.length) throw new Error('malformed partial merkle tree (unused flags/hashes)');
  return {
    root: top.hash,
    matched: top.matches.map((m) => ({ index: m.index, hash: m.leafHash, proof: { index: m.index, branch: m.branch } as MerkleProof })),
  };
}
