# @estates/turn — invariants (every claim is an executable test)

Tests live in `packages/turn/test/turn.test.ts`. Read a claim, find the test, try to
break it.

## Maturity is relative locktime only

| # | Claim | Test |
|---|---|---|
| M1 | Maturity is a relative nSequence window (no CLTV/CSV), sized from params | "maturity is a relative nSequence window (no CLTV/CSV), sized from params" |

## Rules-legal defaults

| # | Claim | Test |
|---|---|---|
| D1 | There is a default branch per actionable phase | "default branch per actionable phase" |
| D2 | The income-levy default picks flat when the seat is wealthy | "income-levy default picks flat when the seat is wealthy" |
| D3 | FORFEIT (AWAIT_ROLL timeout) advances the turn with no move | "FORFEIT (AWAIT_ROLL timeout) advances the turn with no move" |

## Cooperative driver + timeout fallback

| # | Claim | Test |
|---|---|---|
| T1 | `driveTurn` runs a full cooperative turn and advances to the next seat | "driveTurn runs a full cooperative turn and advances to the next seat" |
| T2 | `driveTurn` falls back to the default branch on a missing decision (timeout) | "driveTurn falls back to the default branch on a missing decision (timeout)" |
| T3 | `driveTurn` falls back when a cooperative action is illegal | "driveTurn falls back when a cooperative action is illegal" |

## Bounded game driver

| # | Claim | Test |
|---|---|---|
| B1 | `driveGame` makes progress turn over turn and is bounded | "driveGame makes progress turn over turn and is bounded" |
| B2 | `driveGame` returns immediately when the game is already over | "driveGame returns immediately when the game is already over" |
