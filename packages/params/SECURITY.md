# @estates/params — security boundary

Reference infrastructure: the **single typed accessor for `params/estates.v1.json`**
— the rules source-of-truth. Written so an auditor can attack it.

## What this package is

Every game value derives from here; no number is hard-coded twice. Rents are
**derived** from `base_price + rent_factors` (never stored), so the board and the
economy have one authoritative definition. The JSON is a static import, so the
engine/turn stack is isomorphic (Node `--experimental-strip-types` and the browser
bundler — no `node:fs`).

This package also hosts the **lint-bans** policy tests, the repo-wide gate that keeps
banned constructs (`OP_RETURN`, `CLTV`/`CSV`, branded strings) out of the tree.

## The properties this exists to guarantee

> 1. There is exactly one source of every game value; derived values are consistent.
> 2. The board and decks are structurally well-formed (counts, ids, references).
> 3. The banned-construct gate actually fails on a violation (not just on a clean tree).

- **Single SoT, derived economy:** rents (property/station/utility), mortgage,
  unmortgage, and build costs all derive from the SoT and match it; nothing is stored
  twice to drift out of sync.
- **Structural integrity:** the board has 40 sequential spaces (0..39), exactly 28
  title-NFT spaces (22 properties + 4 stations + 2 utilities), group membership
  references real titled spaces, and each 12-card deck has exactly one Reprieve grant.
- **The gate bites:** lint-bans passes on the clean tree **and** fails on an injected
  `OP_RETURN` and on a branded string — a gate that never fails is no gate.

## Threat model

- A second hard-coded copy of a value drifts from the SoT → derived accessors compute
  from the SoT, so there is no second copy to drift.
- A malformed board/deck (wrong counts, dangling group reference, missing Reprieve) →
  caught by the structural tests.
- A banned construct (`OP_RETURN`, CLTV/CSV, brand string) slips into the tree → the
  lint-bans gate fails the build (proven by the FAIL tests).

## What this package does NOT do

- It does not implement rules logic (`@estates/engine`), only exposes the typed,
  validated values the rules read.
