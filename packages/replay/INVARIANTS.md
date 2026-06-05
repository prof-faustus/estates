# @estates/replay — invariants (every claim is an executable test)

Tests live in `packages/replay/test/replay.test.ts`. Read a claim, find the test,
try to break it.

## Reconstruct from chain data alone (R7)

| # | Claim | Test |
|---|---|---|
| R1 | `readCommit` extracts the on-chain action commitment from a move tx | "readCommit extracts the on-chain action commitment from a move tx" |
| R2 | `replayChain` reconstructs the EXACT final state from chain data alone | "replayChain reconstructs the EXACT final state from chain data alone (R7)" |

## Tamper rejection

| # | Claim | Test |
|---|---|---|
| T1 | A broken link or forged move is rejected | "a broken link or forged move is rejected" |

## SPV-confirmed (no trusted node)

| # | Claim | Test |
|---|---|---|
| S1 | `verifyConfirmedChain`: every move SPV-confirmed AND replays (no node) | "verifyConfirmedChain: every move SPV-confirmed AND replays (no node)" |
