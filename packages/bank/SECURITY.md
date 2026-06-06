# @estates/bank — security boundary

Reference cryptographic infrastructure: the **bank reserve** and its spends. The
bank holds the satoshis that pay salaries, payouts, and card-collect actions, and
holds unowned title NFTs. There is **no trusted banker**. Written so an auditor can
attack it.

## What this package is

Two enforcement modes for spending the reserve, plus the genesis/setup tx:

- **`covenant` (default, trustless):** the reserve sits in a covenant output
  `<rulesHash> <COVENANT_TAG> OP_2DROP OP_TRUE`. A spend is valid **iff its outputs
  match the rules-mandated action and the remainder is re-locked to the SAME
  covenant** — checked with **zero signatures** (in production by Script via
  sighash-preimage introspection / OP_PUSH_TX; here `verifyCovenantPayout` /
  `verifyCovenantSpend` are the equivalent pure predicates). Because validity is
  purely structural, **anyone** can assemble and broadcast a legal payout; the
  "banker" is merely whoever **funded** the reserve and holds **no** spend authority.
- **`quorum` (opt-in, NON-trustless):** an M-of-N threshold over the seat keys. This
  carries an honest-majority TRUST ASSUMPTION, so `verifyReserveSpend` **refuses it by
  default** — a caller must pass `allowQuorum: true` (test / non-production only). A
  production verifier that does not opt in therefore accepts only the trustless covenant.

`reserveOutput(mode, …)` builds the reserve leg for the chosen mode; `buildGenesis`
mints every 1-sat NFT and funds seats + reserve in one tx.

## The properties this exists to guarantee

> 1. The reserve cannot be drained beyond a rules-legal payout.
> 2. A reserve belongs to **exactly one game** and is worthless in any other.
> 3. No party needs to be trusted or online to prevent theft (covenant mode).

### 1 — the covenant self-enforces the payout

`verifyCovenantPayout(prev, tx, recipientPkh, amount)` accepts **iff**, with no
signatures: `output[0]` pays **exactly** `amount` to **exactly** `recipientPkh`, and
`output[1]` re-locks **exactly** `prev.reserve − amount` to the **same** covenant
script. Over-paying, paying the wrong recipient, or failing to re-lock the remainder
are all rejected — the reserve cannot leak. `verifyCovenantSpend` additionally binds
the predicate **to the chain**: the tx must actually spend the named covenant
outpoint, and that input's previous locking script must be exactly this covenant's
script (so the rules hash / reserve are pinned to the real UTXO, audit #8).

`recipientPkh` / `amount` are the canonical values the **deterministic engine**
mandates for the current state; the caller derives them from state, and the residual
re-lock binds the rules hash, so a wrong-rules spend cannot validate.

### 2 — one-game binding (rulesHash(gameId))

`rulesHash(gameId)` folds a 32-byte game id (`ESTATES-BANK-RULES-v1 ‖ gameId ‖
params`) into the rule-set hash, so **each game's covenant is a distinct script**. If
the hash pinned only the params, every game with the same params would lock its
reserve identically — making reserves **fungible across concurrent games** (a payout
assembled against one game's covenant would be structurally valid against another's;
ledger/manifest checks could not tell two games' reserves apart). The gameId fold
makes a reserve worthless outside the game that created it — the same one-game
binding the seat keys (`@estates/keylife`) and title/Reprieve NFTs (`gameTag`) carry.
`rulesHash` is fail-closed: a non-32-byte gameId throws; covenant mode without a
game-bound rules hash refuses to build (`reserveOutput`).

### 3 — no trusted party (covenant mode)

The banker never signs. A non-playing bankroller (`makeBanker(keys, null)`) or a
seated player can fund the reserve and then go offline; neither can cheat, because
validity is structural and game-bound.

## Threat model

- An attacker assembles a tx that pays themselves / over-pays / keeps the full
  reserve while paying out → rejected by the covenant predicate.
- A payout assembled against **game A**'s reserve is replayed against **game B**'s
  reserve → rejected (distinct game-bound script; residual cannot re-lock B).
- A spend that does not actually spend the covenant UTXO, or names a different prev
  script (different rules hash) → rejected by `verifyCovenantSpend`.
- Quorum mode: fewer than threshold signatures, a non-seat signer, or a duplicate
  signer counting twice → rejected; a signature lifted onto a tampered tx → invalid.
- A non-32-byte / malformed gameId → `rulesHash` throws (fail closed), never a
  game-agnostic covenant.

## What this package does NOT do

- It does not decide **what** the legal payout is — that is the deterministic engine
  (`@estates/engine`). The covenant enforces that a spend matches the supplied legal
  action; the caller must supply the engine's canonical `recipientPkh`/`amount`.
- The production on-chain enforcement is Script (OP_PUSH_TX) introspection; the pure
  predicates here are the audited reference the Script must match (`@estates/scriptvm`
  proves the covenant output is spendable with an empty scriptSig).
