# @estates/txmap — invariants (every claim is an executable test)

Tests live in `packages/txmap/test/txmap.test.ts`. Read a claim, find the test, try to
break it.

## Round-trip

| # | Claim | Test |
|---|---|---|
| R1 | Every action type encodes and decodes back to itself | "decodeActionCommit is STRICT: a tagged-but-garbage blob never yields a malformed Action" (regression half) + the existing encode/decode round-trip test |

## Strict decode (on-chain blob is untrusted)

| # | Claim | Test |
|---|---|---|
| D1 | A blob without the tag is rejected ("not an ESTATES move") | the existing `assert.throws(... /not an ESTATES move/)` test |
| D2 | A tagged blob that is truncated, carries an unknown code, an out-of-range actor/propertyId/seat/dice, an invalid PAY_TAX choice, or trailing garbage is rejected — never a malformed Action | "decodeActionCommit is STRICT: a tagged-but-garbage blob never yields a malformed Action" |

## Totality / DoS resistance

| # | Claim | Test |
|---|---|---|
| V1 | 50k random (and tagged-random) blobs only throw or decode to a well-formed move; never hang | "decodeActionCommit is FUZZ-PROOF: 50k random (and tagged-random) blobs never hang; only throw or decode" |

## How to attack this package (auditor guide)

1. Publish a commitment with the right tag but `propertyId = 99` (or `actor = 9`, or
   `seat = 9`) → must throw (out of range), not decode to a bad `Action` (D2).
2. Publish a `ROLL` commitment with dice `9,9`, or only one die → throws (D2).
3. Append one extra byte after a valid move → throws (no trailing garbage) (D2).
4. Truncate a move mid-header → throws ("too short"), no `undefined` field (D2).
5. Fuzz with random and tag-prefixed random blobs (V1). A hang, or a decode to a
   malformed `Action`, is a finding.
