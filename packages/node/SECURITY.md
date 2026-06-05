# @estates/node — security boundary

Reference cryptographic infrastructure: the **native node adapter** (no third-party
REST). It speaks your own BSV node's JSON-RPC to broadcast a move and to fetch a real
SPV proof (`gettxoutproof` → a CMerkleBlock), which it parses and hands to
`@estates/spv` to verify against the block header. Written so an auditor can attack it.

## What this package is

- (de)serialization of a CMerkleBlock (`serializeMerkleBlock` / `parseMerkleBlock`) and a
  block header — pure, isomorphic, tested offline.
- `proofFromMerkleBlockHex` — extract a verifiable inclusion proof for a txid from a
  CMerkleBlock hex.
- `rpc` / broadcast / `getProof` — JSON-RPC calls to your node (online).

## Threat model

A `gettxoutproof` response is **untrusted bytes**: the node may be hostile, compromised,
or MITM'd. A crafted CMerkleBlock can carry:

- a length prefix / varint hash-count or flag-count far larger than the bytes present
  (memory-exhaustion DoS — a naive loop would `push` billions of 32-byte slices);
- a `txCount` of `2^31` to make the downstream tree math hang / overflow the stack;
- truncated fields, or trailing garbage.

A light client must never trust the node's *assertion* that a tx is in a block — only the
proof math, re-verified against a trusted header.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `parseMerkleBlock(bytes)` | **Fully untrusted** | **Total, bounded.** Returns `MerkleBlock \| null`, never throws. Caps the whole frame (16 MiB), requires the header + txCount + ≥1 byte, bounds `txCount` to `1..2^25`, honours a hash/flag count ONLY if the bytes to back it are present and ≤ txCount-derived limits (no over-allocation), and rejects trailing garbage. |
| `proofFromMerkleBlockHex(hex, txid)` | **Fully untrusted** | Total: `null` on bad hex, a wrong-length txid, a malformed block, or a structurally-inconsistent PMT (the `parsePartialMerkleTree` throw is caught). |
| `parseHeader` | **Untrusted** | Throws on `< 80` bytes; only ever called by `parseMerkleBlock`, which guards length first. |
| `rpc` / `broadcast` / `getProof` | **Network I/O** | Talk to YOUR node over authenticated JSON-RPC; the returned proof is still re-verified by math, not trusted. |

## Invariants (each is a test — see INVARIANTS.md)

- **Round-trip + verify:** a CMerkleBlock built from known leaves parses to a proof that
  verifies against the header for every leaf.
- **Total + bounded:** a hostile CMerkleBlock (huge counts, missing backing bytes, 2^31
  txCount, trailing garbage) returns `null` — never throws, allocates, or hangs.
- **Fuzz-proof:** 50k random blobs never make parse throw or hang.

## What must never be assumed

- That a varint count is backed by real bytes — every count is checked against the
  remaining length before any allocation.
- That `txCount` is sane — bounded to `2^25` so the tree math cannot wrap/overflow.
- That the node is honest — the proof is verified by recomputed-root math against a
  trusted header, not by the node's word.

## Known non-goals

- Authenticating the *header* itself (proof-of-work / chain selection) — that is the
  SPV/header-chain layer's job; here the header is the trust anchor passed to `@estates/spv`.
- TLS/transport security of the RPC channel (your node, your loopback / network).
