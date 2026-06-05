# @estates/keylife — invariants (every claim is an executable test)

Tests live in `packages/keylife/test/keylife.test.ts`. Read a claim, find the test, try
to break it.

## Manifest integrity

| # | Claim | Test |
|---|---|---|
| K1 | A well-formed one-game key manifest verifies | "a well-formed one-game key manifest verifies" |
| K2 | A tampered manifest (added/changed key, changed gameId/paramsHash) is rejected — the authority signature binds every entry | "a TAMPERED manifest (added/changed key) is rejected …" |
| K3 | A key reused for two purposes/seats inside one game is rejected | "a key reused for two purposes/seats INSIDE one game is rejected" |
| K4 | Exactly one genesis authority is required | "a manifest without exactly one genesis authority is rejected" |

## Cross-game / expiry

| # | Claim | Test |
|---|---|---|
| X1 | The same key under two different game ids is rejected; fresh keys across games pass | "CROSS-GAME REUSE is rejected: the same key under two different game ids fails" |
| X2 | A key valid in game N is rejected in game N+1 (one-game expiry) | "ONE-GAME EXPIRY: a key valid in game N is rejected in game N+1" |

## Totality / DoS

| # | Claim | Test |
|---|---|---|
| V1 | `verifyManifest` is fail-closed on hostile input (never throws) | "verifyManifest is FAIL-CLOSED on hostile input (never throws)" |
| V2 | 20k random manifests never throw | "verifyManifest is FUZZ-PROOF: 20k random manifests never throw" |

## How to attack this package (auditor guide)

1. Take a valid manifest, swap one seat's key without re-signing → rejected (K2). Change
   `gameId` or `paramsHash` → rejected (the keys are bound to a specific game/ruleset).
2. List the same pub twice (two purposes / two seats) → rejected (K3). Omit or duplicate
   the genesis authority → rejected (K4).
3. Build two manifests with different `gameId`s sharing a key (re-sign each so both are
   internally valid) → `verifyNoCrossGameReuse` rejects (X1).
4. Use a game-A key in game B and call `assertFreshForGame(key, B, manifestB, [A])` →
   rejected as expired (X2).
5. Fuzz `verifyManifest` with random objects (V1/V2). Any throw is a finding.
