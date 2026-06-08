# ESTATES Game — reference

The estate game (Monopoly-class) is played peer-to-peer as your identity, with money in the built-in SPV
wallet and property deeds held as NFTs owned by your identity. This document specifies the lobby, a game's
lifecycle, moves, and how money/NFTs/identity link in.

---

## 1. Lobby & discovery

There is no server and no URL. Nodes discover each other by serverless multicast and form a direct mesh;
an estate-gossip overlay relays peers/offers across the mesh so the lobby shows who is live right now
(including transitively-discovered peers). You see other players by their identity handle.

## 2. Lifecycle

Lobby → fund your wallet (a real on-chain payment to your address) → open or join a table → start → play
your seat → settle. Closing the window ends the session (guaranteed termination); when the human closes,
any bots they ran close and refund first.

## 3. Moves

Each move is signed in-process by the wallet and propagated peer-to-peer as a transaction-carried message
(commit/reveal for dice, etc.). The game never mines; the estate node is SPV + gossip only. Moves are
applied locally and shared; rejected moves are logged with a reason.

## 4. Money

Funds live in the SPV wallet. Payments between players (rent, purchases, settlements) use the one
payment path: pay an address / identity-handle / bot#id / contact. SPV proofs travel with the money so a
payee can verify a payment was mined without querying a node. No coin is ever stranded.

## 5. Deeds as NFTs

Buying a property records its deed as an NFT owned by your identity (`_heldNfts`, persisted to
`%APPDATA%/Estates/nfts.txt`, shown in the NFTs tab as a card owned by the identity). The identity card
links a player's games and history.

## 6. Identity

You join and play as your identity (handle + base identity key). Wallet, chat, and game all key off the
same identity, so a player is one coherent on-chain entity. Chat to opponents by identity (Direct ECDH or
Broadcast key-graph to a chosen subset), and pay them by identity.

## 7. Bots

Bots are seats the human runs and controls (separate persistent wallet per fixed id); they play their seat
inside a real funded game and refund the funder on close. They never make gameplay decisions for the human.

---

*Part of the exhaustive ESTATES reference documentation; grows with the code.*
