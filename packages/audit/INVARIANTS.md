# @estates/audit — invariants (every claim is an executable test)

Tests live in `packages/audit/test/audit.test.ts`. Read a claim, find the test, try to
break it.

## Soundness

| # | Claim | Test |
|---|---|---|
| S1 | A genuine recorded transcript reconstructs and verifies; the result is deterministic | the happy-path audit tests |
| S2 | A tampered roll (chosen dice / swapped reveal / missing commitment) is rejected | the roll-tampering tests |
| S3 | An illegal action is rejected with the engine's reject code | the illegal-action tests |
| S4 | A wrong final hash is rejected ("does not reconstruct the claimed result") | the final-hash-mismatch test |

## Totality / DoS resistance (the transcript is untrusted)

| # | Claim | Test |
|---|---|---|
| V1 | A malformed genesis (incl. seatCount 1e9), non-array entries, bad-hex commits, unknown action → {ok:false}, never throw or OOM | "audit is FAIL-CLOSED on hostile transcripts (bad genesis, bad hex, non-arrays) — never throws or OOMs" |
| V2 | 20k mutated transcripts never throw | "audit is FUZZ-PROOF: 20k mutated transcripts never throw" |

## How to attack this package (auditor guide)

1. Submit a transcript with `genesis.seatCount = 1e9`. `audit` must reject it WITHOUT
   allocating a billion seats — if it hangs/OOMs, that is a DoS finding (V1).
2. Put a non-hex `c` in a roll's commits → rejected (fromHex throw is caught), not a crash
   (V1).
3. Make `entries` a string, or an entry's `commits` a string → `{ok:false}` (V1).
4. Take a genuine transcript and change one roll's dice, or swap a reveal, or drop a
   commitment → rejected by the beacon verifier (S2).
5. Insert an action the engine rejects in that phase → rejected with the code (S3).
6. Keep every entry valid but change `finalHash` → rejected (S4).
7. Fuzz with mutated transcripts (V2). Any throw is a finding.
