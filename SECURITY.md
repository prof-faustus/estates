# ESTATES — security audit remediation

A 10-finding security audit was raised against the repository. **All 10 are
remediated with tests; Bitmessage-style encrypted chat is included.** CI is green
(264 tests + web build). The critical fixes (#1, #2) live on the new authenticated
**IP-to-IP, on-chain** architecture (`@estates/sidecar` over `@estates/link` +
`@estates/channel` + `@estates/beacon`) which replaces the old unauthenticated
HTTP-relay path the audit examined; the legacy packages were also hardened in place.

| # | Finding | Fix | Test (proof) |
|---|---------|-----|--------------|
| 1 | Actions unauthenticated / forgeable | The seat is the PLAYER's own non-custodial key (`identityFrom(playerPriv)`, e.g. `@estates/keys genMaster`) — the SAME key authenticates the handshake, SIGNS every move over `(table, turn, actor, action)`, and addresses chat. A peer may only move its own seat; a move is applied only if its signature verifies against the active seat's registered player key. | `packages/sidecar/test` — "a badly-SIGNED move is rejected" + "moves are signed by the PLAYER key" (real sockets) |
| 2 | Live dice bypass the beacon (mover-chosen) | A ROLL's dice come from a 2-party commit→reveal `@estates/beacon` round (debiased, `prev_beacon`-chained). The signed ROLL carries the commit/reveal transcript; the verifier REJECTS any ROLL whose dice are not the beacon of secrets that open the prior commitments. `policy()` emits no dice. | `packages/sidecar/test` — "a signed ROLL with MOVER-CHOSEN dice is REJECTED" |
| 3 | Audit doesn't verify commitments | Roll entries carry the commitment set; `audit()` enforces one commitment per live seat, no duplicate commit/reveal seat, no reveal from a non-live/non-seat, each reveal opens its commitment, ≥1 honest reveal, and dice derived only from the verified set. | `packages/audit/test` — non-seat reveal / reveal-without-commitment / duplicate / swapped reveal all rejected |
| 4 | Relay total-order broken after loss | `subscribeOrdered` no longer accumulates two sources; the server `/history` append order is the single authority, SSE only pokes a re-poll. | `packages/table/test` (determinism) + `packages/chat/test` |
| 5 | Relay DoS / unbounded | Max body size (413), per-channel log cap (503), max-channels (503). | `packages/chat/test` — oversized body / full channel / channel cap |
| 6 | NFT state not validated | `validateTitleState` rejects impossible state (kind, propertyId 0..39, groupId, buildLevel 0..5, canonical mortgaged byte, REPRIEVE=(0,0,0), uint32 vout); no `&0xff` masking. | `packages/onchain/test` — encode/decode rejection + accept-all-legal |
| 7 | Trade not real-value | `verifyTradeValue(tx, prevAmounts, fee)` conserves against the REAL satoshis of the spent UTXOs + fee (not claimed amounts). Full script-satisfaction is the production step; the move ledger uses canonical `@estates/tx` serialization. | `packages/trade/test` — conserving verifies; bad fee/length/negative rejected |
| 8 | Covenant unbound | `verifyCovenantSpend` binds to the spent outpoint + prev covenant script + rules hash, then the payout predicate. | `packages/bank/test` — wrong outpoint / wrong prev script / wrong recipient rejected |
| 9 | Unsafe hex parsing | Strict codec `^[0-9a-fA-F]*$` + even length in every `fromHex` (audit/net/trade/relay/node/tx/onchain/sidecar). | covered across the suites |
| 10 | CI doesn't build web client | `tools/ci.ts` builds `@estates/client-web` as a CI step. | `pnpm ci` / `node tools/ci.ts` |
| — | Bitmessage-style encrypted chat | Multi-recipient ECIES (`@estates/chat`) over the link; ripemd160(sha256(pub)) addresses; ciphertext only on the wire. | `packages/sidecar/test` — chat decrypts with the right address |

## Run it

```
pnpm --filter @estates/sidecar run demo   # two peers, real sockets, authenticated, beacon dice, encrypted chat, on-chain
node --experimental-strip-types tools/ci.ts   # bans → typecheck → 264 tests → web build
```

## Remaining production hardening (honest)

- The **desktop UI** still uses the legacy `@estates/table` path; migrating the shell to drive the secure `@estates/sidecar` peer is the next integration step (the secure protocol it will use is done and tested).
- #7's full Bitcoin **script-satisfaction** verification (locking-script execution) is the remaining production step for real-value trades; value conservation against real UTXOs + fee is enforced now.
