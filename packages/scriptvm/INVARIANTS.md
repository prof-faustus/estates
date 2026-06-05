# @estates/scriptvm — invariants (every claim is an executable test)

Tests live in `packages/scriptvm/test/scriptvm.test.ts`. Read a claim, find the test, try
to break it.

## Satisfaction (the happy path)

| # | Claim | Test |
|---|---|---|
| S1 | A real ECDSA-signed P2PKH input satisfies its prevout (BIP-143 + OP_CHECKSIG); fee = in − out | "a real ECDSA-signed P2PKH input satisfies its prevout (BIP-143 sighash + OP_CHECKSIG)" |
| S2 | The bank covenant `OP_TRUE` output is spendable with an empty scriptSig | "the bank covenant output (OP_TRUE predicate) is spendable with an empty scriptSig" |

## Authenticity (BIP-143 binding)

| # | Claim | Test |
|---|---|---|
| B1 | A wrong-key / tampered signature does NOT satisfy the prevout | "a WRONG key / tampered sig does NOT satisfy the prevout" |
| B2 | A signature over a different prevout amount fails (value is bound) | "a signature over a DIFFERENT amount fails (BIP-143 binds the prevout value)" |

## Policy

| # | Claim | Test |
|---|---|---|
| P1 | A negative fee (outputs exceed inputs) is rejected | "verifyTx rejects a NEGATIVE fee and a BANNED opcode in an output" |
| P2 | A banned opcode in an output is rejected | same test |

## Totality / DoS resistance (scripts are untrusted bytes)

| # | Claim | Test |
|---|---|---|
| V1 | Hostile scripts (truncated push, non-push scriptSig, banned op, bad DER) yield `{ok:false}`, never throw | "verifyInput is FAIL-CLOSED on hostile scripts (truncated push, non-push sig, banned op, bad DER)" |
| V2 | 50k random scriptSig+prevout pairs never make verifyInput/verifyTx throw or hang | "verifyInput / verifyTx are FUZZ-PROOF: 50k random scriptSig+prevout pairs never throw or hang" |

## How to attack this package (auditor guide)

1. Put a truncated push (`0x05 01 02`) or `OP_PUSHDATA2 ff ff 01` in the scriptSig →
   `{ok:false}`, never a throw (V1).
2. Make the scriptSig carry an opcode (e.g. `OP_DUP`) → rejected as not push-only (V1).
3. Sign correctly but for a prevout value of 9999, verify against the real 2000 → fails
   (B2). Sign with the wrong key → fails (B1).
4. Craft an output script with `OP_RETURN` → `verifyTx` rejects it (P2). Make outputs
   exceed inputs → negative-fee rejection (P1).
5. Feed `OP_CHECKSIG` a garbage DER sig / off-curve pubkey → the check is false, not a
   throw (V1).
6. Fuzz `verifyInput`/`verifyTx` with random scripts (V2). Any throw/hang is a finding.
