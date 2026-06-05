# @estates/node — invariants (every claim is an executable test)

Tests live in `packages/node/test/node.test.ts`. Read a claim, find the test, try to
break it.

## Correctness

| # | Claim | Test |
|---|---|---|
| C1 | A block header round-trips through serialize/parse | "block header round-trips through serialize/parse" |
| C2 | Flag bits pack/unpack (LSB-first) round-trip | "flag bits pack/unpack (LSB-first) round-trip" |
| C3 | A CMerkleBlock serialize→parse→proof verifies against the header, for every leaf | "CMerkleBlock serialize→parse→proof verifies against the header (native node SPV)" |
| C4 | A txid not in the block yields no proof (null) | "proofFromMerkleBlockHex returns null for a txid not in the block" |

## Totality / DoS resistance (the proof is untrusted bytes)

| # | Claim | Test |
|---|---|---|
| V1 | A hostile CMerkleBlock (huge/un-backed counts, truncated, trailing garbage) returns null — no throw, no allocation | "parseMerkleBlock rejects hostile CMerkleBlocks without throwing or allocating" |
| V2 | A 2^31 txCount is rejected immediately — no hang, no stack overflow | "parseMerkleBlock with a 2^31 txCount does not hang or stack-overflow" |
| V3 | 50k random blobs never make parse throw or hang | "parseMerkleBlock / proofFromMerkleBlockHex are FUZZ-PROOF: 50k random blobs never throw" |

## How to attack this package (auditor guide)

1. Return a CMerkleBlock whose hash-count varint is `0xff…` but with no hash bytes after
   it → must be `null`, with no billion-element allocation (V1).
2. Claim one 32-byte hash but supply only 16 bytes → `null` (V1).
3. Set `txCount = 0x80000000` → rejected in well under a frame, no spin/overflow (V2).
4. Append trailing bytes after a valid proof → `null` (no parse ambiguity) (V1).
5. Fuzz `parseMerkleBlock`/`proofFromMerkleBlockHex` with random blobs (V3). Any
   throw/hang is a finding.
6. Even a *well-formed* proof must still be re-verified: confirm the extracted branch is
   checked against a trusted header by `@estates/spv` (C3), not trusted on the node's word.
