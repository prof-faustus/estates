# @estates/merkleblock — invariants (every claim is an executable test)

Tests live in `packages/merkleblock/test/` and (for the byte boundary) in
`packages/node/test/node.test.ts`.

## Correctness

| # | Claim | Test |
|---|---|---|
| C1 | build→parse recomputes the same root and each matched leaf's proof verifies | "build→parse round-trips: root matches and the matched leaf's proof verifies" |
| C2 | A node-supplied CMerkleBlock parses to a proof that verifies against the header | "CMerkleBlock serialize→parse→proof verifies against the header (native node SPV)" (in @estates/node) |

## Bounded / DoS resistance

| # | Claim | Test (in @estates/node) |
|---|---|---|
| V1 | An out-of-range `txCount` (2^31) is rejected immediately — no treeHeight spin, no stack overflow | "parseMerkleBlock with a 2^31 txCount does not hang or stack-overflow" |
| V2 | A huge hash/flag count with no backing bytes is rejected without allocation | "parseMerkleBlock rejects hostile CMerkleBlocks without throwing or allocating" |
| V3 | 50k random blobs never make parse throw or hang | "parseMerkleBlock / proofFromMerkleBlockHex are FUZZ-PROOF: 50k random blobs never throw" |

## How to attack this package (auditor guide)

1. Supply a PMT with `txCount = 0x80000000`. `parsePartialMerkleTree` must reject it
   (txCount out of range) — if it spins or overflows the stack, that is a DoS finding (V1).
2. Supply `hashes.length > txCount`, or a hash that is not 32 bytes, or
   `flags.length > 2·txCount+8` → rejected before tree math (V2).
3. Feed a structurally-inconsistent-but-bounded proof (unused hashes / non-zero flag
   padding) → a defined throw the boundary catches as "reject" (C1's negative side).
