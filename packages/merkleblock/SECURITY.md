# @estates/merkleblock — security boundary

Reference cryptographic infrastructure: the **BIP-37 partial Merkle tree** — exactly
what a BSV node returns from `gettxoutproof`. A light client uses it to recompute a
block's Merkle root and extract an inclusion branch, trusting the proof's MATH, not the
node. Written so an auditor can attack it.

## What this package is

`buildPartialMerkleTree` produces a PMT for matched leaf indexes (proof-serving / test
vectors). `parsePartialMerkleTree` consumes a PMT, recomputes the root in one pass, and
emits an `@estates/spv`-compatible inclusion proof for each matched leaf. Both round-trip
with `@estates/spv` (`buildProof`/`verifyInclusion`).

## Threat model

The PMT is **untrusted**: it arrives (via `@estates/node`'s `parseMerkleBlock`) from a
node that may be hostile or MITM'd. The dangerous fields are all attacker-controlled:

- `txCount` — drives the tree height. A naive `treeHeight` loop `while ((1<<h) < n)`
  **hangs** for a huge `n`, because in JS `1<<h` is evaluated mod-32 and so never exceeds
  a large `n`. The traversal also recurses to depth `treeHeight(n)` — a huge height is a
  **stack overflow**.
- `hashes` — an over-long or wrong-sized list.
- `flags` — an over-long bit list.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `parsePartialMerkleTree(pmt)` | **Untrusted shape** | Validates `txCount` (integer, `1..MAX_TREE_LEAVES = 2^25`), `hashes` (≤ txCount, each exactly 32 bytes), and `flags` (≤ `2·txCount+8`) BEFORE any tree math. Within that bound every `1<<height` stays < 2^31 (no wrap) and recursion depth ≤ 25. Throws a well-defined `Error` on a structurally-inconsistent (but bounded) proof — its caller (`parseMerkleBlock`/`proofFromMerkleBlockHex`) treats that as "reject". |
| `buildPartialMerkleTree` | **Trusted** (our own leaves) | Builds a proof from a known leaf set. |
| `MAX_TREE_LEAVES` | constant | The cap that makes all the bit-shift tree math overflow-safe. |

## Invariants (each is a test — see INVARIANTS.md)

- **Round-trip:** build→parse recomputes the same root and each matched leaf's proof
  verifies under `@estates/spv`.
- **Bounded:** an out-of-range `txCount`, an over-long `hashes`/`flags`, or a wrong-sized
  hash is rejected before tree math — never a hang, never a stack overflow.

## What must never be assumed

- That `txCount` is a sane integer — it is bounded to `MAX_TREE_LEAVES`, which is what
  keeps `1<<height` from wrapping.
- That `hashes`/`flags` lengths are consistent with `txCount` — both are bounded first.

## Known non-goals

- Header validity / proof-of-work (the caller verifies the recomputed root against a
  trusted `BlockHeader` in `@estates/spv`).
