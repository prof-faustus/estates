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

**Phase 0 complete** (repository reconciliation): protocol binding, decisions, the
single-source-of-truth params, and the CI static bans are in place and green.
Phases 1–6 (deterministic core + lobby + beacon → board engine → on-chain objects
& trade → bot → graphical client → full game/audit/packaging) follow.

## Toolchain

Node ≥24 (runs `.ts` via `--experimental-strip-types`), pnpm 9, TypeScript 5.8.

```
pnpm lint:bans   # static bans (must pass)
pnpm typecheck
pnpm test
pnpm ci          # full pipeline
```
