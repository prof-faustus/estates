# @estates/cli — invariants (every claim is an executable test)

Tests live in `packages/cli/test/cli.test.ts`. Read a claim, find the test, try to
break it.

## Real on-chain table genesis

| # | Claim | Test |
|---|---|---|
| T1 | Table genesis funds N seats + a covenant reserve, signed, as a real BSV tx | "table genesis: funds N seats + a covenant reserve, signed, real BSV tx" |
| T2 | The seat count is configurable | "seat count is configurable" |

## Notes

- The reserve output carries the **game-bound** covenant script (`rulesHash(gameId)`);
  the genesis test asserts the reserve script equals `covenantOutput(reserve,
  rulesHash(GAME))`.
- Money guards (mainnet confirmation, regtest rpc) are enforced in and tested by
  `@estates/wallet`; the CLI threads `--confirm-real-value` / node config through.
