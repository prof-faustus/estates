# @estates/bot — security boundary

Reference infrastructure: **bot policies as turn-driver deciders** — for offline
practice and as deterministic test drivers. Written so an auditor can attack it.

## What this package is

A policy maps the current state to the active seat's action (roll with beacon-backed
dice, buy/decline, pick the cheaper income levy, build on full groups, else end the
turn). Deterministic given `(state, policy, dice)`, so bot play is auditable and
replayable like everything else. Each bot carries an **independent secp256k1 signing
identity** (its own keys).

## The properties this exists to guarantee

> 1. Bots play only legal, deterministic actions (no special powers, no hidden RNG).
> 2. Bot play conserves money exactly like human play.
> 3. Bots are clearly non-authoritative: human-control and trustless rules still hold.

- **Deterministic & legal:** every policy choice is a function of public state +
  dice; a long self-play run conserves money and never drives a balance negative,
  across all three policies.
- **Independent identity:** each bot has distinct keys; one bot cannot sign for
  another or for a human.
- **Bounded role:** dice come from the beacon-backed source, not the bot; the bot
  proposes ordinary actions the engine validates like any seat's.

## Threat model & explicit limits

- **In-process bots are NOT trustless.** In a trustless game a bot runs as its own
  process/host with its own keys; in-process use here is explicitly **offline
  practice / tests only**. This is stated in the source header and honoured by the
  human-control rule: a person selects every real action; bots never choose actions
  in a real multiplayer game.
- A bot attempts an illegal/out-of-phase action → rejected by `@estates/engine` like
  any seat.
- A bot tries to act for another seat → blocked by distinct signing identities.
- **Fund-return rule (project invariant):** a sim/bot player must return 100% of its
  wallet to its funding source on close (see `@estates/wallet` `drainTo`); leftover
  funds are a hard failure.

## What this package does NOT do

- It makes no decision for a human in a real game; it is a practice/test driver.
  Real games are human-driven (`@estates/turn` cooperative path), with the engine as
  the sole legality authority.
