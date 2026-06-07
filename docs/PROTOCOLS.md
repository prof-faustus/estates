# ESTATES transaction-type protocol suite

The blockchain (BSV) is the network/IP layer. Each **ESTATES transaction type** is its own protocol
on top — like HTTP, SMTP, … each ride TCP/IP yet are distinct. Every type has a unique **protocol
number**, a self-identifying **header** that can always be extracted as a layer, its own documented
**template** (transaction/script shape), and its own smart contract. No type shares another's form;
none is generic.

## Self-identifying header

The first pushdata of a typed transaction's marker output is a 6-byte header:

```
magic(3) = "EST"  ‖  type(2, little-endian protocol number)  ‖  version(1)
```

Any peer reads this to learn exactly what a transaction is for — exactly as one reads the protocol
field over IP. `TxProtocol.Read(data)` returns `(type, version, payload)` or null (not ours).

The marker rides a 1-sat data output: `<header‖payload> OP_DROP P2PKH(owner)` — state on-chain,
still spendable, **no OP_RETURN**.

## Protocol numbers

| # | Type | Template / purpose |
|---|------|--------------------|
| 1 | PAYMENT | Plain value transfer (P2PKH) — the base template. |
| 2 | CHAT-2P | Two-person encrypted chat. Payload: senderPub‖nonce‖ciphertext, AES-256 key = secp256k1 ECDH x-coord (no ephemeral key). |
| 3 | CHAT-GROUP | Group chat under the broadcast key-graph (GB 2623780 B); content key wrapped to each member. |
| 4 | NFT-MINT | Mint a true encrypted NFT (card/deed) to an owner: 1-sat output, face ECDH+AES-sealed to the owner. |
| 5 | NFT-TRANSFER | Spend the old NFT outpoint and re-seal the face to the new owner (digital scarcity: old copy dead). |
| 6 | COMMITMENT | A commit (mental-poker shuffle / dice beacon). Payload: 32-byte commitment. |
| 7 | REVEAL | Reveal opening a prior commitment. Payload: the secret. |
| 8 | KEEPALIVE | Presence heartbeat — itself a transaction. Empty payload. |
| 9 | MOVE | A game move. Payload: the move commitment. |
| 10 | AUCTION-BID | Conditional auction bid (OP_PUSH_TX covenant): win → pay grantor + role NFT; refund → outbid/closed. |
| 11 | ROLE-GRANT | Award of an auctioned role (banker, dealer, …). |
| 12 | DEAL | An on-chain card deal. |
| 13 | TRADE | Peer-to-peer NFT/asset trade — atomic swap. |
| 14 | TABLE-OPEN | Open a table. |
| 15 | GAME-START | Start a game. |

Numbers are durable and never reused. New types take the next number and are added here.

## Atomic swaps

Every exchange of value/ownership — NFT-TRANSFER, TRADE, ROLE-GRANT, DEAL — settles as an **atomic
swap**: a single transaction that moves both sides at once, or neither. There is no trusted
intermediary and no half-completed exchange.

## Encryption

The only asymmetric encryption is **ECDH with an AES key** (no ephemeral-key scheme): the two parties' own
secp256k1 keys do ECDH; the shared-secret x-coordinate is the AES-256 key; AES-256-GCM encrypts.
Group secrecy uses the broadcast key-graph (content key wrapped per member).
