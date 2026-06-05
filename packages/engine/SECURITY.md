# @estates/engine — security boundary

Reference infrastructure: the **pure deterministic ESTATES core**. `apply(state,
action) → new state | typed rejection`. No I/O, no clock, no own randomness.
Written so an auditor can attack it.

## What this package is

The single source of truth for the rules. Every transition is recomputable from the
transcript: **dice arrive on `ROLL` actions** (from the dealerless beacon, never
self-generated) and **deck order is injected at init** (from the dealerless shuffle).
Given the same initial config and the same ordered action list, every peer — web or
native — computes the identical state, byte-for-byte (this is what
`@estates/conformance` and the native `Estates.Core` cross-validate).

## The properties this exists to guarantee

> 1. Determinism: identical action sequences yield identical states.
> 2. Value conservation: satoshis are conserved (seats + bank) and no balance goes
>    negative.
> 3. No illegal transition: wrong-phase / illegal actions are rejected, not applied.
> 4. Fairness gate: a live game refuses to start without a real committed deck order.

- **Determinism / no own randomness:** the engine never calls a clock or RNG; dice
  are inputs, deck order is injected. So a replay (web NetTable or native
  GameReplay) of the same transcript reproduces the same canonical state hash.
- **Fairness gate:** `requireFairDecks` rejects a missing or biased `deckOrder` and
  accepts only a real permutation of `[0,n)` — a live game cannot start with a
  dealer-chosen or absent deck order.
- **Conservation:** money moves between seats and the bank reserve; the totals are
  conserved and no balance is allowed to go negative. Raise-funds auto-mortgages
  rather than over-drawing; bankruptcy auto-liquidates deterministically (sell
  buildings, then mortgage) before removing a seat.
- **Total rejection:** an action in the wrong phase, an illegal build (not a full
  group / breaks even-build / no house supply), an unaffordable action, etc., return
  a typed rejection and leave state unchanged — never a partial mutation.

## Threat model

- A client submits a raw `ROLL` with chosen dice → in multiplayer the table layer
  drops raw rolls (dice come from the beacon); the engine treats dice as the given
  input for replay, so the authoritative dice are the beacon's.
- A client submits an out-of-phase or illegal action → rejected, state unchanged.
- A config without a fair deck order tries to start a live game → rejected by the
  fairness gate.
- An action sequence that would create or destroy value → conservation holds; no
  negative balances.
- Two peers diverge → impossible for the same transcript (determinism), caught by
  conformance + native parity.

## What this package does NOT do

- It does not produce randomness or talk to the chain/relay. Dice come from
  `@estates/beacon`, deck order from `@estates/deck`, transport from `@estates/table`,
  on-chain settlement from `@estates/ledger` + `@estates/bank`.
- It does not make any decision on the human's behalf — every action is chosen by a
  person; the engine only validates and applies.
