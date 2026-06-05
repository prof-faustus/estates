# @estates/turn — security boundary

Reference infrastructure: **cooperative + timeout-default turn driver**. Every
actionable FSM state has a cooperative transition AND a pre-signed default branch.
Written so an auditor can attack it.

## What this package is

`defaultActionFor` gives the rules §7 default for the current phase; `driveTurn` runs
one full turn cooperatively, falling back to the default when a seat's decision is
absent (a timeout). A default branch is broadcastable only after a **relative**
maturity window expressed purely as `nSequence` (relative locktime) — **never
CLTV/CSV**. The window is the data the on-chain default-branch transaction binds.

## The properties this exists to guarantee

> 1. A turn always makes legal progress, even if a seat goes silent (liveness).
> 2. A silent seat's fallback is a pre-defined, rules-legal default — not a choice
>    made for them.
> 3. Timing uses relative locktime only (no CLTV/CSV).

- **Liveness without coercion:** if a seat's cooperative action is missing, the turn
  takes the rules-mandated default (e.g. FORFEIT on an AWAIT_ROLL timeout advances
  the turn with no move); a wealthy seat's income-levy default is the flat option.
- **Illegal cooperative action → default:** if a supplied cooperative action is
  illegal, the driver falls back to the legal default rather than applying garbage.
- **Bounded game driver:** `driveGame` makes progress turn over turn and is bounded
  (cannot loop forever); it returns immediately when the game is already over.
- **Relative maturity only:** the default branch matures on an `nSequence` window
  sized from params — no CLTV/CSV (consistent with the repo-wide ban).

## Threat model

- A seat stalls to freeze the game → the timeout default advances it (liveness).
- A malicious/garbled cooperative action → rejected; the legal default is applied.
- A default branch broadcast before maturity → gated by the relative `nSequence`
  window (the tx layer enforces it on-chain).
- A driver that loops forever on a degenerate game → bounded by construction.

## What this package does NOT do

- It does not decide a human's actual move (humans choose cooperatively); it only
  supplies the rules-legal default when a decision is absent, and validates via
  `@estates/engine`. The on-chain default-branch tx is bound by the Phase-3 tx layer.
