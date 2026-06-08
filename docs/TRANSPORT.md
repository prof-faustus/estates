# ESTATES Transport — reference

Everything that crosses between machines in ESTATES is a Bitcoin transaction. There is no raw,
non-transaction packet carrying content, no chat/presence/game message bus, and no central relay. This
document specifies the carrier model, dual propagation, and receipt.

---

## 1. The rule

Every inter-machine communication — a payment, a chat message, a game move, a fund offer, a refund ack — is
a BSV transaction. Content rides in a **carrier output**: a single pushdata of the (encrypted) payload
followed by `OP_DROP` and a normal P2PKH (`OnChainActions.CarrierScript` / `TxTransport.MessageOutput`). No
`OP_RETURN`; the output stays spendable by its owner.

## 2. Sealing

A typed message is sealed before it becomes a carrier: `TxMessage.SealCarrier(senderMsgPriv, recipientPub,
TxType, plaintext)` stamps a protocol header (magic + version + type) and encrypts the body to the
recipient (static ECDH + AES-GCM, sender's per-message Type-42 key). Broadcast chat instead embeds a
key-graph frame (`ChatCodec`) as the carrier, already ciphertext.

## 3. Dual propagation

`TxTransport.SendAsync` sends the raw transaction BOTH ways:

1. **IP-to-IP** to every connected peer over the direct mesh links (instant delivery to players/bots), and
2. **on-chain** by broadcasting to mining nodes for inclusion.

The player path does not wait on a block; the proof of a payment (the SPV envelope) is handed over the
same link. Estate gossip frames are magic-prefixed (`EGSP`) so gossip and transaction frames never collide.

## 4. Receipt

Incoming bytes are parsed AS a transaction (`Tx.Parse`); each output's carrier is read
(`TxTransport.ReadCarrier`) and opened with the recipient's key (`TxMessage.OpenCarrier` /
`TxTransport.Extract`), or, for broadcast chat, via `ChatCodec.Open`. Malformed/hostile bytes parse to null
and are ignored — a peer-link callback can never crash the app (all handlers are guarded, heavy work
off-thread).

## 5. Typed messages

`TxType` enumerates the protocol: Payment, Chat2P, ChatGroup, NftMint/Transfer, Commitment/Reveal,
KeepAlive, Move, AuctionBid, RoleGrant, Deal, Trade, TableOpen, GameStart, Identity, BotFundOffer,
BotRefund, GameClose. One transport carries them all.

## 6. Why this design

- **No off-chain side channels:** value and messages share one auditable, encryptable, on-chain-capable
  medium. Off-chain comms, play-money, or free NFTs would be a fundamental breach.
- **Always-online, instant:** direct IP delivery means no polling a server; broadcasting in parallel gets
  the transaction mined.
- **Serverless:** the mesh + multicast discovery + gossip overlay need no central component.

---

*Part of the exhaustive ESTATES reference documentation; grows with the code.*
