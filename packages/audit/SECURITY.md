# @estates/audit — security boundary

Reference cryptographic infrastructure: the **independent verifier** — it reconstructs a
whole ESTATES game from its transcript and re-checks every dice roll (against the beacon)
and every action (through the pure engine), with no trust in the player who produced it.
This is the proof that a game reconstructs and verifies "from chain alone" (design spec
R7). Written so an auditor can attack it.

## What this package is

- `recordGame(...)` — produce a `GameTranscript` (roll entries carry commitments + reveals
  + claimed dice; action entries carry the action).
- `audit(t)` — independently replay `t`: re-derive every roll from its reveals (chaining
  `prev_beacon`), re-check every action through `apply`, and confirm the final state hash.

## Threat model

A transcript reconstructed "from chain alone" is **untrusted** — produced by a possibly
hostile player or relayed by a hostile node. It may carry:

- a malformed `genesis` (wrong network, or `seatCount: 1e9` to make `initialState`
  allocate a billion seats — a DoS that a `try/catch` cannot undo);
- `entries` that is not an array;
- a roll entry whose `commits`/`reveals` are not arrays, or whose `c`/`secret` are not hex
  (so `fromHex` would throw out of the loop);
- an action entry whose `action` is unknown / `__proto__` / malformed;
- a wrong final hash.

`audit` must return a clean `{ok:false, reason}` for every one of these — never throw,
never allocate on an attacker-chosen count.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `audit(t)` | **Fully untrusted** | **Total.** Validates `t` is an object, the params version, and the `genesis` (network ∈ {regtest,testnet,mainnet}; `seatCount` integer 2..8; `bankReserve` integer ≥0) BEFORE `initialState` — so the 1e9-seat allocation can never happen. `entries` must be an array; each entry's shape is checked; the whole replay loop runs inside a `try/catch` so a bad-hex / malformed entry is a clean reject. Never throws. |
| `recordGame` | **Trusted** (our own play) | Produces a canonical transcript. |
| `verifyRollEntry` (`@estates/beacon`) | shared | The SAME roll verifier `@estates/net` uses — commitments + participant set + openings + canonical dice. |

## Invariants (each is a test — see INVARIANTS.md)

- **Soundness:** a genuine transcript verifies; any tampered roll (chosen dice, swapped
  reveal, missing commitment), illegal action, or wrong final hash is rejected.
- **Totality / DoS:** a malformed genesis (incl. 1e9 seats), non-array entries, bad-hex
  commits, or an unknown action makes `audit` return `{ok:false}` — never throw or OOM.
  20k mutated transcripts never throw.

## What must never be assumed

- That `genesis.seatCount` is sane — it is bounded to 2..8 before `initialState`.
- That `entries`/`commits`/`reveals` are arrays of valid-hex entries — re-checked; the
  replay is guarded.
- That a transcript is honest because it has the right shape — every roll and action is
  re-verified, and the final hash must match.

## Known non-goals

- Confirming the transcript's entries are actually on chain (that is the SPV layer's job:
  `@estates/beef`/`spv`/`node`); `audit` proves the *game logic + dice* reconstruct.
