# @estates/deck — invariants (every claim is an executable test)

Tests live in `packages/deck/test/deck.test.ts`. Read a claim, find the test, try to
break it.

## Concealment & binding

| # | Claim | Test |
|---|---|---|
| C1 | A sealed face opens only for the holder; a wrong key / tamper yields null | the seal/open round-trip + wrong-key tests |
| C2 | The commitment binds the face (no swap); a card is worthless at another table | the openCard happy-path + wrong-table tests |
| C3 | The dealerless shuffle is unbiased for every ESTATES set size (rejection sampling) | the permutation/shuffle tests |

## One-use keys (enforced, not just claimed)

| # | Claim | Test |
|---|---|---|
| K1 | A reused `cardPub`, an off-curve `cardPub`, or a wrong-table card fails verifyCardTranscript | the verifyCardTranscript tests |

## Totality (a malicious minter / random data)

| # | Claim | Test |
|---|---|---|
| V1 | A minter who committed+sealed a MALFORMED face makes openCard return null, never throw | "openCard returns null (never throws) on a MALICIOUS minter who committed to a malformed face" |
| V2 | decodeFace rejects short/malformed buffers; openCard is fuzz-proof over 20k random sealed faces | "decodeFace rejects short/malformed buffers; openCard is FUZZ-PROOF over random sealed faces" |

## How to attack this package (auditor guide)

1. As a malicious minter, commit to garbage face bytes and seal them to the victim. The
   commitment check passes, but the face does not decode — `openCard` must return `null`,
   never throw (V1).
2. Feed `decodeFace` a 3-byte buffer, or a header claiming a payload longer than present →
   a clean throw, never an out-of-bounds read (V2).
3. Build a transcript that transfers a card without re-keying (reused `cardPub`), or with
   an off-curve `cardPub` → `verifyCardTranscript` fails (K1).
4. Re-seal a card to a different table id and present it → rejected by the table binding
   in `openCard`/`verifyCardTranscript` (C2/K1).
5. Fuzz `openCard` with random sealed faces (V2). Any throw is a finding.
