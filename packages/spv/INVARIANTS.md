# @estates/spv — invariants (every claim is an executable test)

Tests live in `packages/spv/test/`. Read a claim, find the test, try to break it.

## Soundness

| # | Claim | Test |
|---|---|---|
| S1 | A valid branch recomputes the header's merkleRoot (inclusion proven) | the build/verify round-trip tests |
| S2 | A forged / wrong-index / wrong-length branch does NOT verify (returns false) | the negative inclusion tests |
| S3 | `verifyInclusion`/`rootFromProof` never throw on a malformed proof — a mismatch is `false` | covered by S2 + `bytesEqual` length handling |

## Trust anchor

| # | Claim | Test |
|---|---|---|
| T1 | Inclusion is accepted only against a caller-supplied merkleRoot/header, never a supplier's word | `verifyAgainstHeader` binds to `header.merkleRoot` |

## How to attack this package (auditor guide)

1. Take a valid proof and flip a sibling hash, or change the index → `verifyInclusion`
   returns `false` (S2). It must never return `true` for a tx not under the root.
2. Supply a branch with a 16-byte sibling → the recomputed root simply mismatches; no
   throw (S3).
3. Supply a huge branch → the work is the branch length (bounded to ≤ 25 by the upstream
   `@estates/merkleblock` parser); a hand-built unbounded branch is the caller's own DoS,
   not a wire path.
4. Try to get inclusion accepted against the *tx's own* asserted root rather than the
   header's → impossible: `verifyAgainstHeader` only ever compares to `header.merkleRoot`
   (T1).
