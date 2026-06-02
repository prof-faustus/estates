# ESTATES

A dealerless, fully-on-chain, fully-auditable property game on **BSV**.

- **Money is native satoshis** (no token); network mode (`mainnet`/`testnet`/`regtest`)
  is fixed at table genesis; **regtest auto-funds** seat balances + bank reserve.
- **Title deeds and Reprieve cards are 1-sat NFTs**, moved by atomic transactions.
- **Provably-fair dice** via commit→reveal (debiased 2d6), publicly recomputable.
- **Non-custodial** per-seat keys; the whole game reconstructs from chain data alone.
- **Original, non-copyright content** only.

## Non-negotiable rules (enforced in CI — `pnpm lint:bans`)

- **OP_RETURN banned** — on-chain data is pushdata in live script (`OP_DROP`/`OP_2DROP`).
- **CLTV / CSV banned** — all timing is `nLockTime` (absolute) + `nSequence` (relative).
- **No branded / trademarked strings** — original expression only.
- **Single source of truth:** every parameter derives from [`params/estates.v1.json`](params/estates.v1.json).

## Protocol layer

Built on the `prof-faustus/bsv-poker` primitives — see [`PROTOCOL-BINDING.md`](PROTOCOL-BINDING.md)
for the C1–C8 capability bindings. Design decisions: [`DECISIONS.md`](DECISIONS.md).

## Status

- **Phase 0 complete** (`v0.0.0-phase0`): protocol binding, decisions, params SoT, CI bans.
- **Phase 1 complete** (`v0.1.0-phase1`): the deterministic core + lobby + dice beacon,
  with conformance vectors generated from the core.
  - `@estates/engine` — pure turn-FSM core (movement, doubles, holding, salary,
    buy/rent/tax/cards, even-build + supply, mortgage, raise-funds/bankruptcy, win).
  - `@estates/conformance` — 16 `(state, action) → (hash | rejection)` vectors, the
    legality source of truth, re-checked against the live engine.
  - `@estates/beacon` — commit→reveal debiased 2d6 (rejection sampling), `prev_beacon`
    chaining, reveal-drop timeout default (binds C4).
  - `@estates/lobby` — join/ready/start-authority/override-start; network fixed at
    genesis; regtest auto-funding; emits the `EngineConfig` that seeds the core.

- **Phase 2 complete** (`v0.2.0-phase2`): `@estates/turn` — the cooperative/timeout
  default-branch model (each actionable state's default, maturing on an `nSequence`
  relative window; no CLTV/CSV) plus a full-turn/whole-game driver. The engine gained
  a `FORFEIT` action (the AWAIT_ROLL timeout default).

- **Phase 3 complete** (`v0.3.0-phase3`): on-chain objects + trade + auction + bank.
  - `@estates/onchain` — BSV script model (OP_RETURN-banned at serialize), 1-sat
    title/Reprieve NFTs (state as `<push> OP_DROP` + P2PKH), native-sat payments.
  - `@estates/trade` — atomic player↔player trade; secp256k1 `SIGHASH_ALL` co-signing.
  - `@estates/auction` — sealed-bid commit→reveal, highest valid bid wins.
  - `@estates/bank` — M-of-N threshold-guarded reserve spends (D-BANK-ENFORCE v1)
    + the genesis/setup tx minting the NFTs and funding seats + reserve.

- **Phase 4 complete** (`v0.4.0-phase4`): `@estates/bot` — `cautious`/`balanced`/
  `aggressive` policies as turn-driver `Decider`s, each with an independent
  secp256k1 signing identity. Self-play over hundreds of turns proves money is
  conserved (seats + bank reserve) and no balance goes negative — which caught and
  fixed a reserve-debit bug in the engine's auto-liquidation path.

- **Phase 5 complete** (`v0.5.0-phase5`): `@estates/client-web` — React + Vite + **SVG**
  board. Offline-practice mode runs the pure engine **in-browser** (keys never leave
  the client; dice via Web Crypto here, beacon for trustless play). Lobby seat count,
  SVG board with group bands / owner dots / buildings, per-seat NFT+cash panel, dice
  readout, build/buy/tax/end-turn controls, transcript log. This required making
  `@estates/params` **isomorphic** (static JSON import, no `node:fs`) so the engine
  stack bundles for the browser. `vite build` green.

- **Phase 6 — audit/replay (R7)** (`v0.6.0-phase6`): `@estates/audit` — records a
  beacon-backed game transcript and **independently reconstructs + verifies** it:
  every dice roll re-derived from the seats' reveals (chaining `prev_beacon`), every
  action re-checked through the pure engine, and the final state hash confirmed.
  Forged dice, swapped reveals, illegal actions, and wrong final hashes are all
  rejected — the proof that a complete game verifies from chain data alone.

- **Phase 6 integration shipped**: `@estates/net` (C7 untrusted relay transport +
  peer convergence + reconnection), `@estates/chainmap` (engine↔1-sat-NFT bridge),
  **Tauri v2 desktop packaging** (`apps/client-web/src-tauri`) — `tauri build`
  produces `estates-desktop.exe` plus MSI and NSIS installers (Rust 1.96 / WebView2),
  and `@estates/chat` — **multiparty join + broadcast-encrypted chat**: Bitmessage-style
  addresses, multi-recipient ECIES (secp256k1 → HKDF → AES-256-GCM) over the untrusted
  relay; only current members decrypt, revocation + forward-access-control enforced.

Remaining (ops / post-v1): reproducible-from-clean-VM build (the `pnpm reproduce`
script is the deterministic core), and the bank covenant upgrade (D-BANK-ENFORCE,
explicitly post-v1).

## Toolchain

Node ≥24 (runs `.ts` via `--experimental-strip-types`), pnpm 9, TypeScript 5.8.

```
pnpm lint:bans   # static bans (must pass)
pnpm typecheck
pnpm test
pnpm ci          # full pipeline
```
