# @estates/replay — security boundary

Reference infrastructure: **reconstruct and verify a WHOLE game from the on-chain
move chain alone** — the auditability guarantee (R7). Written so an auditor can
attack it.

## What this package is

A third party with only the transcript (the ordered move transactions) and the rules
can: confirm each move links to the previous, decode each move's on-chain commitment
back into its action (`@estates/txmap`), re-execute it through the deterministic
engine, and arrive at the **exact** final state — or reject an illegal/forged move.
With SPV envelopes (`@estates/beef`) it additionally proves every move is confirmed
under proof-of-work, **trusting no node and no operator**.

## The properties this exists to guarantee

> 1. The whole game is reconstructable from chain data alone.
> 2. A broken link or forged/illegal move is rejected — not silently replayed.
> 3. With SPV, every move is proof-of-work-confirmed (no trusted node).

- **Exact reconstruction:** `replayChain` rebuilds the exact final state from the
  ordered move txs + rules — no operator input, no off-chain trust.
- **Tamper rejection:** a move that does not link to its predecessor, or whose decoded
  action is illegal under the engine, is rejected.
- **SPV-confirmed:** `verifyConfirmedChain` requires every move to be SPV-confirmed
  AND to replay — so an unconfirmed or forged move cannot pass even without a node.

## Threat model

- An operator presents a doctored transcript (reordered/forged move) → the link check
  and engine legality reject it.
- A move whose on-chain commitment decodes to an illegal action → rejected on replay.
- A transcript with unconfirmed moves presented as final → `verifyConfirmedChain`
  fails (no SPV proof).
- Hostile/malformed tx or commitment bytes → checks are total (no throw / no silent
  pass).

## What this package does NOT do

- It does not produce moves or talk to a node; it consumes the chain (txs + optional
  SPV envelopes) and verifies. Rules are `@estates/engine`; SPV is `@estates/beef`.
