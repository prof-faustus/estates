# @estates/bot — invariants (every claim is an executable test)

Tests live in `packages/bot/test/bot.test.ts`. Read a claim, find the test, try to
break it.

## Legal, deterministic policy choices

| # | Claim | Test |
|---|---|---|
| P1 | A ROLL action carries in-range dice | "ROLL action carries in-range dice" |
| P2 | Aggressive buys an affordable property; cautious declines when the buffer breaks | "aggressive buys an affordable property; cautious declines when the buffer breaks" |
| P3 | Income levy: the bot always picks the cheaper option | "income levy: bot always picks the cheaper option" |
| P4 | Aggressive builds evenly on an owned full group; cautious holds when short | "aggressive builds evenly on an owned full group; cautious holds when short" |

## Independent identity

| # | Claim | Test |
|---|---|---|
| I1 | Bots have independent signing identities (distinct keys) | "bots have independent signing identities (distinct keys)" |

## Conservation under self-play

| # | Claim | Test |
|---|---|---|
| C1 | Self-play: money is conserved and no balance goes negative over a long game | "self-play: money is conserved and no balance goes negative over a long game" |
| C2 | Self-play across all three policies stays consistent | "self-play across all three policies stays consistent" |
