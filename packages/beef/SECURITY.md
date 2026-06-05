# @estates/beef — security boundary

Reference cryptographic infrastructure: the **SPV envelope** peers exchange IP-to-IP and
verify with NO node and NO third-party API (the BEEF/BRC-62 idea). A move's transaction
travels with the Merkle proof + block header that prove it is confirmed; the receiver
recomputes the leaf, checks inclusion under PoW, and trusts only mathematics — never the
sender or any operator. Written so an auditor can attack it.

## What this package is

- `txLeaf(tx)` — the Merkle leaf `hash256(serializeTx(tx))`.
- `verifyEnvelope(env)` — a tx is confirmed in `env.header`'s block by SPV inclusion alone.
- `verifyPaymentToKey(env, expected)` — inclusion AND that the confirmed tx pays a specific
  value/script (e.g. a one-use key / 1-sat NFT was funded on chain).
- `verifySpendChain(spend, inputEnvelopes)` — every input of an unconfirmed move spends an
  output of a CONFIRMED, SPV-proven tx that actually exists.

## Threat model

An `Envelope` is **untrusted** data from a peer. It may carry:

- a malformed `tx` (missing/ wrong-typed inputs/outputs, a non-bigint value) that would
  throw inside `serializeTx`;
- a forged/short/wrong proof or header (delegated to `@estates/spv`, which returns `false`);
- a tx whose inclusion is real but which does NOT pay what is claimed, or whose outputs
  don't cover the spend's inputs.

The verifiers must return `false`/`{ok:false}` on all of these — never throw, never accept
an unproven or wrongly-paying tx.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `verifyEnvelope(env)` | **Untrusted** | Total: requires `tx`/`proof`/`header`, computes the leaf and checks inclusion inside a guard; a malformed tx (serializeTx throw) is `false`, never an exception. |
| `verifyPaymentToKey(env, expected)` | **Untrusted** | Total: inclusion first, then an exact value+script match at some output; BigInt coercion is guarded. |
| `verifySpendChain(spend, inputEnvelopes)` | **Untrusted** | Total: each input envelope must verify AND its tx must serialize (txid under guard); each `spend` input must reference an existing output of a proven source. Never throws. |

## Invariants (each is a test — see INVARIANTS.md)

- **Inclusion:** a confirmed tx with a valid proof verifies; a forged proof does not.
- **Content:** `verifyPaymentToKey` accepts only the exact value+script actually paid.
- **Custody:** `verifySpendChain` accepts a move only if every input traces to a proven,
  existing confirmed output.
- **Totality:** a malformed envelope (bad tx/proof/header, non-bigint value) returns
  `false`/`{ok:false}`, never throws.

## What must never be assumed

- That `env.tx` is a well-formed `Tx` — `serializeTx`/`txid` are called under guard.
- That the sender's word that a tx is confirmed / pays X is true — only the SPV math and
  the on-chain outputs are trusted.

## Known non-goals

- Proof-of-work / header-chain validity of `env.header` (that is the header-chain layer's
  job; here the header's `merkleRoot` is the inclusion anchor).
- Mempool/double-spend visibility for the *unconfirmed* `spend` itself — its provenance is
  SPV-proven; its own confirmation comes later.
