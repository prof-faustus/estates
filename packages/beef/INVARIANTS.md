# @estates/beef — invariants (every claim is an executable test)

Tests live in `packages/beef/test/beef.test.ts`. Read a claim, find the test, try to
break it.

## Inclusion & content

| # | Claim | Test |
|---|---|---|
| I1 | A confirmed tx with a valid proof verifies against its header | the verifyEnvelope happy-path test |
| I2 | A forged/wrong proof does not verify | the negative verifyEnvelope test |
| I3 | verifyPaymentToKey accepts only the exact value+script actually paid on chain | the verifyPaymentToKey tests |

## Custody

| # | Claim | Test |
|---|---|---|
| K1 | verifySpendChain accepts a move only if every input traces to a proven, existing confirmed output | the verifySpendChain tests |

## Totality

| # | Claim | Test |
|---|---|---|
| V1 | A malformed envelope (bad tx/proof/header, non-bigint value) returns false/{ok:false}, never throws | "verifyEnvelope / verifyPaymentToKey / verifySpendChain are FAIL-CLOSED on malformed envelopes" |

## How to attack this package (auditor guide)

1. Send an envelope whose `tx` is missing inputs/outputs, or has a non-bigint output value
   → the verifiers return `false`, never throw (V1).
2. Send a real tx with a forged Merkle proof → `verifyEnvelope` is `false` (I2).
3. Claim a payment to your key that the confirmed tx does not actually make →
   `verifyPaymentToKey` is `false` (I3).
4. Build a spend whose input references a vout that does not exist in the proven source,
   or a source with no envelope → `verifySpendChain` is `{ok:false}` (K1).
5. Feed `verifySpendChain` a malformed input envelope → `{ok:false}`, never a throw (V1).
