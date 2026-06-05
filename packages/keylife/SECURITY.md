# @estates/keylife — security boundary

Reference cryptographic infrastructure: the **one-game key lifecycle**. The governing
rule — *every cryptographic key the game uses is valid for at most one game* — is made
enforceable here by a signed genesis key manifest + cross-game reuse rejection. Written
so an auditor can attack it.

## What this package is

A `GameKeyManifest` binds every key — seat / card / holder / chat / bank / settlement /
trade — to a single `gameId` + `protocolVersion` + `paramsHash`, signed by a genesis
authority (an Ed25519 key that is itself the sole `purpose:'genesis'` entry). Verifiers
re-validate the manifest and reject any key that appears under two different `gameId`s.

Per-game KEYS are produced by `@estates/channel.gameIdentityFrom(master, gameId)` (the
player's own non-custodial master yields a DISTINCT signing key per game); this package
is the manifest + the verifier that makes "one game per key" enforceable rather than a
convention.

## Threat model

The manifest and the manifest set are **untrusted**:
- a tampered manifest (added / changed / removed key) without re-signing;
- a key reused for two purposes / two seats inside one game;
- a manifest with zero or several genesis authorities;
- the SAME key reappearing under a different `gameId` (cross-game reuse / a key
  outliving its one game);
- malformed / hostile objects (must never throw).

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `buildManifest` | trusted (our genesis) | signs the canonical body with the authority's Ed25519 key. |
| `verifyManifest(m)` | **fully untrusted** | Total: validates `gameId`/`paramsHash`/`authorityPub`/`sig` hex+lengths, bounds `entries` (≤4096), each entry's purpose/keyType/pub-length, NO in-game key reuse, NO duplicate seat, EXACTLY one genesis (== authorityPub), and the authority signature over the canonical body. Returns `{ok,reason}`, never throws. |
| `verifyNoCrossGameReuse(manifests)` | **fully untrusted** | rejects if a pub appears under two different `gameId`s. |
| `assertFreshForGame(pub, gameId, m, priors)` | **fully untrusted** | the key must be bound by this game's manifest and absent from every prior game's manifest (one-game expiry). |

## Invariants (each is a test — see INVARIANTS.md)

- A well-formed manifest verifies; a tampered one (any field) is rejected — the authority
  signature binds every entry.
- A key reused for two purposes/seats in one game is rejected; exactly one genesis.
- Cross-game reuse (same key, two `gameId`s) is rejected.
- One-game expiry: a key valid in game N is rejected in game N+1.
- `verifyManifest` is fail-closed + fuzz-proof on hostile input.

## What must never be assumed

- That listing a key in a manifest is enough — the manifest must be authority-signed and
  the key must not appear in any other game's manifest.
- That keys are one-game because they "should be" — `gameIdentityFrom` derives them
  per-game and the manifest + reuse check enforce it.

## Known non-goals

- Distributing the manifest (the table/relay layer publishes it at `start`).
- Per-key revocation mid-game (a key is bound for the whole game; expiry is per-game).
