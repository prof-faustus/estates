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

Remaining: Phase 3 (on-chain 1-sat NFTs, native-sat payments, bank reserve, atomic
trade, mortgage/build/auction) → Phase 4 (bots) → Phase 5 (React/SVG client) →
Phase 6 (full game, audit/replay, packaging).

## Toolchain

Node ≥24 (runs `.ts` via `--experimental-strip-types`), pnpm 9, TypeScript 5.8.

```
pnpm lint:bans   # static bans (must pass)
pnpm typecheck
pnpm test
pnpm ci          # full pipeline
```
