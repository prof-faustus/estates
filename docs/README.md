# ESTATES — documentation index

Exhaustive reference documentation for ESTATES (native Windows BSV peer-to-peer estate game with a
built-in ElectrumSV-class SPV wallet). Every subsystem documents WHAT it is, HOW it works, and WHY it is
built that way. This set grows with the code toward complete coverage.

## Start here
- [ARCHITECTURE.md](ARCHITECTURE.md) — system overview: process model, subsystems, in-tree crypto,
  one-code-path networks, money-safety invariants, build/verify/deliver.

## Wallet & money
- [WALLET.md](WALLET.md) — the ElectrumSV-class wallet: key architecture, every tab, pay-is-pay,
  identity/NFT/chat/game linkage, BIP38/sweep, money safety.
- [SPV.md](SPV.md) — Craig's SPV: the envelope (tx + merkle proof + header), verification (PoW + merkle),
  the SPV wallet, spending, the BIP37 Bloom filter, node-as-proof-source.

## Identity, chat, bots
- [IDENTITY.md](IDENTITY.md) — base identity key (index 0, ECDH-root, never an address), HMAC hash-chain
  sub-keys, the persistent handle, pay/chat-by-identity, identity↔chat/NFT/game linkage.
- [CHAT.md](CHAT.md) — identity-addressed, end-to-end encrypted chat carried as Bitcoin transactions:
  Direct (ECDH) vs Broadcast (key-graph to a chosen subset), the in-chat command set.
- [BOTS.md](BOTS.md) — separate persistent wallet per fixed bot id, pay-is-pay funding, refund-to-funder
  on close, the absolute close-ordering.

## Status
Measured against the A++ target this is in-progress scaffolding — ElectrumSVP (trusted ElectrumSV fork) is
the C-minus baseline being ported and then exceeded with identity, NFTs, chat-by-identity, the game, a
built-in smart agent, and exhaustive (target: one-million-line) documentation. Not finished.
