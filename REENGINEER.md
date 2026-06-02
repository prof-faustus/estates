# ESTATES — Re-engineering specification (authoritative)

This document supersedes my earlier wrong assumptions. ESTATES is **not** a standalone
game with an off-chain relay. It is a **BSV demonstration**: a property game built as a
module on the **mental-poker** stack, where **every interaction is an on-chain BSV
transaction**, verified by **native SPV** over **IP-to-IP** peers. The game is the demo;
the technology is the point.

The earlier estates build (HTTP relay as source of truth, off-chain engine, WhatsOnChain,
optimistic state) is **discarded as the foundation**. What is reused below is reused from
the author's existing repos — not reinvented.

## Non-negotiable rules (locked)

1. **BSV, not BTC. Maximise on-chain transactions — "spam is good."** The design goal is
   *as many on-chain sends as possible*: billions of transactions per game. Anything that
   reduces tx count to "save" the chain (BTC/Lightning thinking) is wrong.
2. **EVERY move is its own on-chain BSV transaction, without exception, always** — every
   roll, buy, rent, tax, salary, build, mortgage, trade, jail event, auction bid, **every
   chat message**, every field action. 100+ action types. Nothing is off-chain. Nothing is
   batched away. Nothing is a payment channel.
3. **Whole satoshis only. No sub-satoshis. No payment channels.** Players fund the game
   with sats; every move sends sats on-chain.
4. **Native SPV, no third-party middleman.** Verification is BEEF/BUMP Merkle proofs
   against block headers, served by the player's **own native SPV node** over **IP-to-IP**
   peer connections. **WhatsOnChain / any third-party REST as a trusted source is BANNED.**
   REST *is allowed* only as the **local loopback API of your own native node/sidecar**
   (the UI calls the local node over REST; the node does the BSV P2P + SPV natively).
5. **Mental poker is the substrate.** ESTATES is a `GameModule` registered into the
   **bsv-poker SDK** (`registerGame('estates', …)`), reusing `@bsv-poker/*`. The dealerless
   randomness, concealed deck, commit/reveal, and settlement come from there.
6. **Every property AND every card is an ENCRYPTED 1-sat NFT, each with its own wallet/key**
   (one-use keys; static reusable addresses are banned). All are **created at table genesis**,
   **concealed via mental poker** (like a poker deck), and **issued/revealed per the rules**.
   Players hold their own NFTs.
7. **NFTs are tradeable peer-to-peer** (Alice→Bob via a single atomic swap tx, SIGHASH_ALL),
   but are **table-bound**: valid only within the table they were minted for (the table-genesis
   id is baked into the token; an NFT from one table is worthless at another).
8. **Human controls every action; menu-driven everywhere; no defaults that act.** Bots are
   **separate remote players** (own process/window, own keys/funds, over the wire), never
   in-app. Network (regtest/testnet/mainnet) is user-selected, never defaulted. Desktop
   (Tauri) is the deliverable. Exhaustively self-tested before any handover.

## The stack to bind to (reuse, do not reinvent)

| Capability | Source repo (author's) | What it gives |
|---|---|---|
| Mental poker + SDK + engine | `D:\claude\Mental Poker\bsv-poker` — `@bsv-poker/crypto-mentalpoker`, `@bsv-poker/engine` (GameModule), `@bsv-poker/sdk` (`registerGame`/`getGame`/`createSdk`), `@bsv-poker/app-services`, `@bsv-poker/tx-builder`, `@bsv-poker/script-templates-ts`, `@bsv-poker/wallet-custody` | concealed deck, entropy commit→reveal, distributed shuffle, GameModule FSM, tx building, custody |
| Native SPV node + IP-to-IP | `D:\claude\SPV\01-spv-p2p` (BEEF/BUMP header store, **BRC-103** authenticated IP-to-IP channels, **BRC-29** single-use payment keys) and `D:\claude\cardtable-zh\apps\relay-go\cmd\spv` (standalone SPV daemon) + its TCP/WebSocket peer transport | header sync, Merkle-proof verification, direct peer sockets, one-use payment keys |
| Encrypted-NFT + one-use ECDH keys | `D:\claude\SPVNFT` — `ecdh-singleuse` (ephemeral key → ECDH → KEK → AES-256-GCM), 1-sat carrier outputs, SIGHASH_ALL atomic swaps, native node adapter + SPV merkle verify, loopback sidecar pattern | encrypted NFT cards, one-use keys, atomic transfer, native chain access |

ESTATES binds at the **source level** (pnpm workspace path references to the sibling repos),
per `PROTOCOL-BINDING.md`.

## Target architecture

- **estates game module** (`@bsv-poker/game-estates` or `@estates/game`): authors the property
  turn-FSM as a `GameModule` (init/apply/getLegalActions/isTimeoutEligible/settle/serialize),
  registered into the bsv-poker SDK. Reuses the engine, deck concealment, and settlement.
- **Deck of encrypted NFTs**: at genesis, mint every deed + Reprieve + Fate/Treasury card as a
  1-sat NFT, each with its own one-use key, face encrypted and committed (mental poker), table
  -bound (table-genesis id in the token state). Cards are dealt/issued/revealed per the rules;
  ownership transfer = atomic swap tx.
- **Every action → a BSV tx**: extend the engine→tx mapping so all 100+ interactions (incl.
  chat) each emit a signed on-chain tx; whole sats; pushdata+OP_DROP state (no OP_RETURN);
  timing via nLockTime/nSequence (no CLTV/CSV).
- **Native SPV node sidecar**: a local process does BSV P2P (broadcast every tx) + SPV
  (BEEF/BUMP verify) over IP-to-IP, exposing a loopback REST API to the desktop UI. No
  WhatsOnChain. Networks user-selected; regtest = the user's own node.
- **Desktop**: Tauri shell; UI is menu-driven; bots are separate remote player processes.

## Build order (verifiable layers — each proven before the next)

0. **Bind** estates → bsv-poker SDK + the SPV/IP-to-IP/SPVNFT packages (workspace path refs);
   stand up the native SPV node sidecar; CI bans stay green.
1. **Encrypted table-bound 1-sat NFT card model** (each NFT own one-use key; mental-poker
   conceal/reveal; atomic Alice→Bob swap) — with conformance tests.
2. **estates GameModule** authored against `@bsv-poker/engine`, registered in the SDK; the deck
   = the encrypted NFTs; dice = the mental-poker beacon.
3. **Every action → on-chain BSV tx** (whole sats, native broadcast + SPV verify over IP-to-IP);
   remove WhatsOnChain entirely. Chat is on-chain too.
4. **Desktop** wiring: UI over the loopback node REST; separate bot-player processes; network
   selection; exhaustive self-test on the user's regtest node.

This is a large cross-repo rebuild (estimate: many weeks), executed in the above layers and
proven on the user's `nftbsv-regtest` node — never reported "done" until every interaction is
an on-chain BSV tx verified by native SPV.
