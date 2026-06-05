# @estates/keys — invariants (every claim is an executable test)

Tests live in `packages/keys/test/keys.test.ts`. Read a claim, find the test, try to
break it.

## BRC-42 derivation correctness

| # | Claim | Test |
|---|---|---|
| K1 | Sender-derived child pubkey == the pubkey of the recipient-derived child privkey | "BRC-42 shared derivation: sender pubkey == recipient privkey’s pubkey" |
| K2 | Derivation is deterministic and per-invoice unique (a hash chain) | "shared derivation is deterministic and per-invoice unique (a hash chain)" |
| K3 | Derived private keys are valid secp256k1 scalars (0 < k < n) | "derived private keys are valid secp256k1 scalars" |

## Outsider exclusion

| # | Claim | Test |
|---|---|---|
| X1 | An outsider with the wrong counterparty cannot derive the same key | "an outsider (wrong counterparty) cannot derive the same key" |

## One-use, no reuse

| # | Claim | Test |
|---|---|---|
| R1 | `deriveSelf` issues indexed one-use keys: deterministic, all distinct, none equals the master | "deriveSelf: indexed one-use keys, deterministic, all distinct, none is the master" |
| R2 | `KeyChain.next()` issues a fresh one-use key every time (no reuse) | "KeyChain.next() issues a fresh one-use key every time (no reuse)" |
| R3 | `spendContext` binds each output: different purpose/role/turn/output ⇒ different key | "spendContext binds each output: different purpose/role/turn/output ⇒ different key (no reuse)" |

## Pay / receive recoverability

| # | Claim | Test |
|---|---|---|
| P1 | A KeyChain pay/receive round-trips between two parties | "KeyChain pay/receive round-trips between two parties" |
| P2 | A payer-derived output pkh is recoverable by the recipient (pkhOf + spendContext) | "pkhOf + spendContext: a payer-derived output pkh is recoverable by the recipient" |
