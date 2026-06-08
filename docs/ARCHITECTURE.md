# ESTATES — architecture overview

ESTATES is a native Windows (`estates.exe`, WPF, self-contained single file) BSV peer-to-peer estate game
with a built-in, ElectrumSV-class SPV wallet. It is **pure peer-to-peer** — zero central infrastructure —
and everything that crosses machines is a Bitcoin transaction. This document ties the parts together; each
subsystem has its own deeper reference.

---

## 1. Process model

One process. A player runs `estates.exe`; a bot is the same binary run as `estates.exe --bot --id N`. There
is no server, no daemon, no child keep-alive. Closing the window terminates every thread and socket
(`ShutdownMode.OnLastWindowClose` + a hard-exit backstop), so the session is guaranteed to end.

## 2. Subsystems

| Subsystem | Role | Reference |
|-----------|------|-----------|
| **Wallet** | In-process SPV wallet; ElectrumSV-style tabbed UI; pay anything (address/identity/contact/invoice). | [WALLET.md](WALLET.md) |
| **SPV** | Craig's SPV: coins delivered IP-to-IP as tx + merkle proof + header; verified + stored; Bloom matching. | [SPV.md](SPV.md) |
| **Identity** | Base identity key (index 0, ECDH-root, never an address) + HMAC hash-chain sub-keys; persistent handle. | [IDENTITY.md](IDENTITY.md) |
| **Keys** | One seed → `KeyRing` (identity + sub-keys) + `Type42` ECDH; encrypted at rest (`WalletStore`). | IDENTITY.md / WALLET.md |
| **Transport** | Every inter-machine message is a BSV transaction carrier, sent IP-to-IP to peers (and to miners on-chain). | (transport) |
| **P2P / gossip** | Serverless multicast discovery + a mesh of direct links; an estate-gossip overlay relays peers/offers. | (p2p) |
| **Chat** | Identity-addressed: Direct (ECDH) or Broadcast (key-graph to a chosen subset); in-chat commands. | IDENTITY.md |
| **Bots** | Separate persistent wallet per fixed bot id; funded by paying their address; refund the funder on close. | (bots) |
| **Game** | Played as the identity; deeds/cards are NFTs owned by the identity. | (game) |

## 3. Cryptography (all in-tree, no third-party libs)

secp256k1 (ECDSA low-S, ECDH, point compress/decompress), SHA-256/256d, RIPEMD-160, AES-256-GCM,
Base58Check, FORKID sighash + OP_CHECKSIG (`Scriptvm`), merkle proofs, BIP37 Bloom (MurmurHash3),
scrypt (RFC 7914) for BIP38, Type-42/HMAC key derivation, the GB 2623780 B broadcast key-graph. Ed25519
and any non-secp256k1 curve are banned. BIP32/39/44 are banned for key derivation (BIP270 — the BSV
payment protocol — is supported and is unrelated).

## 4. Networks

One code path for **regtest / testnet / mainnet**; the network is a config tag + node endpoint, never a
branch. A global network selector appears on every screen (regtest password-gated). RPC ports: regtest
18443, testnet 18332, mainnet 8332 (proof source only).

## 5. Money-safety invariants

- Keys encrypted at rest (AES-256-GCM + PBKDF2-SHA256, 200 000 iters); wrong password fails closed.
- The base identity key never appears on chain; addresses are sub-keys (index ≥ 1); fresh per payment.
- The wallet creation wizard forces a seed backup before a wallet exists.
- An existing wallet is never silently replaced (explicit typed `REPLACE`); Save Copy backs it up.
- Bots refund the funder 100% on close; on a human close, bots close + refund first.
- No coin is ever stranded; SPV proofs are stored and re-handed with spends.

## 6. Build / verify / deliver

Build with the .NET SDK; the conformance harness (`Estates.Conformance`) is the executed green-run
evidence for the in-tree crypto (positive + hostile-negative tests). Each iteration: build → conformance →
publish single-file `estates.exe` to the repo root → commit + push (public). The GUI is never launched on
the user's machine by the agent; the user runs it.

## 7. Status

This is groundbreaking, in-progress work — measured against the A++ target it is early scaffolding, not
finished. ElectrumSVP (a trusted ElectrumSV fork) is the C-minus baseline being ported and then exceeded
with identity, NFTs, chat-by-identity, the game, a built-in smart agent, and exhaustive (target: one
million line) documentation.

---

*Part of the exhaustive ESTATES reference documentation; grows with the code.*
