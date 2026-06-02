# PROTOCOL-BINDING.md — ESTATES ↔ bsv-poker

Maps each required-capability contract **C1–C8** (design spec §3) to a **real symbol**
in the authoritative `prof-faustus/bsv-poker` repository (read at tag `v0.3.0`,
HEAD `92bb025`), or marks it **ABSENT** (to be built to the contract).

> **Authority rule:** the repository wins over the specs. Symbols below were read
> from the repo source, not assumed from the spec.

bsv-poker is a pnpm TS monorepo shipping packages as raw `.ts`
(`exports["."] = "./src/index.ts"`, run under Node ≥24 `--experimental-strip-types`).
Import specifiers are the real ones.

| Contract | Capability | Binding (repo symbol → import) | Status |
|---|---|---|---|
| **C1** | Identity & keys (non-custodial, deterministic derivation, signing) | `createSoftwareCustody()`, `Custody` (`derive(gid,j,role)`, `sign(...)`) → `@bsv-poker/wallet-custody`; `genKeyPair`, `compressedPub`, `KeyPair` → `@bsv-poker/script-templates-ts` | **BOUND** |
| **C2** | Tx construction & signing; per-input SIGHASH; multi-party co-sign of one tx | `Tx`, `TxInput`(`.sequence`), `TxOutput`, `sighashPreimage`, `txid`, `withMaturity`, `build*` → `@bsv-poker/tx-builder`; `signPreimage`, locking/unlocking templates, `Script`, `pushData`, `serializeScript` → `@bsv-poker/script-templates-ts` | **BOUND** |
| **C3** | Broadcast & SPV (Merkle inclusion vs headers, no trusted full node) | `IndexerClient`, `RelayClient.publish` → `@bsv-poker/app-services`; Go services `apps/relay-go`, `apps/indexer-go`. SPV merkle-proof verification surface = **PARTIAL** (relay/indexer projection exists; standalone SPV proof verifier to be confirmed/built) | **PARTIAL** |
| **C4** | Verifiable randomness (commit→reveal, unbiasable, recomputable transcript) | `makeRealCT()`, `entropyCommitSync`, `permutationFromEntropy`, `combinedSeed`, `shuffledDeck` → `@bsv-poker/crypto-mentalpoker`; contract types `CTContract` → `@bsv-poker/adapters`. **Used for the dice beacon** (debiased 2d6 by rejection sampling; ESTATES adds the 2d6 map + `prev_beacon` chaining). | **BOUND** |
| **C5** | 1-sat NFT construction (state in live script, transfer by spend) | **No NFT/token/ordinal builder in repo.** Build to tx-nft doc §3 on top of `@bsv-poker/script-templates-ts` (`<state…> OP_DROP` + P2PKH predicate). | **ABSENT — BUILD** |
| **C6** | Selective reveal / concealed objects (hidden decks, sealed bids) | `makeRealCT()` conceal/verifyReveal + `combinedKey` → `@bsv-poker/crypto-mentalpoker`; reveal modes via `Custody.decryptToViewer` → `@bsv-poker/wallet-custody` | **BOUND** |
| **C7** | Peer transport & discovery | `RelayClient` (`heartbeat`/presence, `createTable`/`listTables`, `subscribe` SSE, `publish`), `IndexerClient`; lobby/table clients → `@bsv-poker/app-services`. Transport is **HTTP + SSE over `fetch`** (not raw WebSocket). | **BOUND** |
| **C8** | Timeout / default branches via `nLockTime`+`nSequence` (no CLTV/CSV) | `withMaturity(tx, nLockTime)` (sets nLockTime, clamps `sequence` to `0xfffffffe`) → `@bsv-poker/tx-builder`; `revealOrTimeoutLocking`/`timeoutRefundUnlocking` ELSE-branch → `@bsv-poker/script-templates-ts`; `GameModule.isTimeoutEligible`, `TimeoutResolution` → `@bsv-poker/engine` | **BOUND** |

Supporting bindings used by Phase 1+:
- **Deterministic state engine / replay:** `replay()`, `GameModule.apply` → `@bsv-poker/engine` (pure; no I/O/clock/RNG). ESTATES authors its own `GameModule` for the turn FSM.
- **Wire / serialization / hashing:** `ByteWriter`, `BranchBinding`, `bindingBytes`, sha256/hash256 → `@bsv-poker/protocol-types` / `@bsv-poker/script-templates-ts`.

## O2 — randomness primitive vs OP_RETURN (CLOSED)

**Determination: the repo primitive does NOT use OP_RETURN.** `@bsv-poker/crypto-mentalpoker`
is pure JS (HMAC/SHA-256/ECDH) and emits no script. On-chain commitments are carried as
**`<pushdata> OP_DROP`** inside live spendable script (`branchBindingPrefix` →
`[bindingBytes(b), OP.OP_DROP]`). The ban is enforced in-repo at three layers
(`BANNED_OPCODES`, `serializeScript()` throws, interpreter rejects). **No replacement
needed**; ESTATES inherits the same pushdata-in-live-script convention. (Closes the
kickoff Phase-0 O2 obligation.)

## CLTV / CSV (compliant)

`OP_CHECKLOCKTIMEVERIFY`/`OP_CHECKSEQUENCEVERIFY` are **defined** as opcodes in the repo
but appear in **no template**; the interpreter treats them as NO-OPs and a negative test
asserts such scripts are rejected. Timing is `nLockTime`/`nSequence` only. The repo has an
OP_RETURN source-lint (`tools/lint-opreturn.ts`) but **no** CLTV/CSV source-lint — ESTATES
adds one (see `tools/lint-bans.ts`).

## Cross-repo consumption

bsv-poker is a local sibling repo (`D:\claude\Mental Poker\bsv-poker`), not published to a
registry. ESTATES binds at the **source level**: Phase 1+ vendors the needed `@bsv-poker/*`
packages via a pnpm workspace path reference (or git submodule pin to `v0.3.0`+), recorded
here when wired. Phase 0 (this document, DECISIONS, params SoT, CI bans) needs no import.

## Open obligations carried forward

- **O1** — confirm/adapt SPV merkle-proof verification for C3 (PARTIAL above).
- **O2** — CLOSED (above).
- **C5** — NFT construction is ABSENT; build to tx-nft §3 in Phase 3 (title/Reprieve 1-sat NFTs).
- **D-BANK-ENFORCE** — v1 M-of-N threshold; covenant upgrade later (DECISIONS.md).
