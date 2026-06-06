# @estates/bank — invariants (every claim is an executable test)

Tests live in `packages/bank/test/covenant.test.ts` and
`packages/bank/test/bank.test.ts`. Read a claim, find the test, try to break it.

## Trustless covenant (default; no signatures, no trusted banker)

| # | Claim | Test |
|---|---|---|
| C1 | A rules-legal payout verifies with ZERO signatures (validity is purely structural) | "trustless payout: a legal payout verifies with ZERO signatures" |
| C2 | Over-draining the reserve (residual not reduced) is rejected | "over-draining the reserve is rejected by the covenant" |
| C3 | Paying the wrong recipient is rejected | "paying the wrong recipient is rejected" |
| C4 | Paying more than the legal amount is rejected | "paying more than the legal amount is rejected" |
| C5 | Failing to re-lock the remainder to the covenant is rejected (reserve cannot leak) | "failing to re-lock the remainder to the covenant is rejected" |
| C6 | A payout exceeding the reserve is rejected | "a payout exceeding the reserve is rejected" |
| C7 | The banker holds NO spend authority: a non-playing bankroller (seat = null) or a seated player can fund it; neither signs | "a non-playing bankroller can be the banker (seat = null) and holds no spend authority" |

## Bound to the chain (audit #8)

| # | Claim | Test |
|---|---|---|
| B1 | A spend must actually spend the named covenant outpoint AND the prev script must be exactly this covenant; wrong outpoint, wrong prev script, or wrong recipient/amount are all rejected | "verifyCovenantSpend binds to the spent outpoint AND the prev covenant script" |
| B2 | The covenant pins the rule-set hash: a mismatched rules hash does not re-lock | "the covenant pins the rule-set hash (mismatched rules do not re-lock)" |

## One-game lifecycle (rulesHash(gameId))

| # | Claim | Test |
|---|---|---|
| G1 | A different gameId yields a DISTINCT reserve script (two games never share a covenant) | "the covenant is bound to one game: a different gameId yields a DISTINCT script" |
| G2 | A payout assembled for one game does NOT validate against another game's reserve | "a payout assembled for one game does NOT validate against another game reserve" |
| G3 | `rulesHash` rejects a non-32-byte gameId (fail closed) | "rulesHash rejects a non-32-byte gameId (fail closed)" |
| G4 | A bank `purchase` must move THIS game's NFT; a foreign-game deed is rejected (non-NFT actions pass; bad gameId fails closed) | "bankActionBelongsToGame: a purchase must move THIS game’s NFT; a foreign-game deed is rejected" |

## Quorum mode (opt-in M-of-N fallback)

| # | Claim | Test |
|---|---|---|
| Q1 | Fewer than threshold valid seat signatures is invalid; ≥ threshold is valid | "M-of-N: fewer than threshold signatures is invalid; threshold is valid" |
| Q2 | A non-seat key and duplicate signers do not count toward the threshold | "a non-seat key and duplicate signers do not count toward the threshold" |
| Q3 | A signature does not transfer across tampered outputs (sign one tx, alter it → invalid) | "signatures do not transfer across tampered outputs (sign one tx, alter it)" |
| Q4 | Both enforcement modes verify a legal reserve spend (quorum and covenant) | "reserve enforcement choice: quorum (M-of-N) and covenant (trustless) both verify" |

## Genesis / setup

| # | Claim | Test |
|---|---|---|
| S1 | `certifyBankAction` accepts the legal output set and rejects an illegal one | "certify accepts the legal output set and rejects an illegal one" |
| S2 | The genesis tx mints all 1-sat NFTs and funds seats + reserve | "genesis tx mints all 1-sat NFTs and funds seats + reserve" |
| S3 | Every genesis output is accounted for (no unexplained outputs) | "genesis output count is fully accounted for" |
