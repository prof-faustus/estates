# ESTATES Chat — reference

Chat in ESTATES is identity-addressed, end-to-end encrypted, and **carried entirely as Bitcoin
transactions** delivered IP-to-IP. There is no chat server and no off-chain message bus. This document
specifies the two encryption modes, the wire model, and the in-chat command set.

---

## 1. Wire model — every message is a transaction

A chat message is serialised (`Messenger.Serialize`), sealed, embedded as a carrier output in a BSV
transaction (pushdata + OP_DROP + P2PKH, no OP_RETURN), and sent over each live peer link
(`TxTransport` / `TxMessage`). The receiver parses incoming bytes as a transaction and extracts the
carrier addressed to it. No raw, non-transaction packet carries content between machines.

## 2. Direct mode (two-person ECDH)

`TxType.Chat2P`. The message is sealed to ONE identity using static secp256k1 ECDH between the sender's
per-message key (Type-42, advanced per message) and the recipient's identity/wallet pubkey, then AES-GCM.
Only that recipient can open it. Used when you pick a single peer/identity to message.

## 3. Broadcast mode (key-graph to a chosen subset)

The GB 2623780 B broadcast key-graph (`ChatCodec` / `Broadcast`). The message is broadcast-encrypted
ONCE; each chosen member's leaf key is delivered by two-person ECDH. A non-member has no leaf and cannot
reach the message key — ciphertext only on the wire. The sender picks the subset (e.g. 10 of 100 — not
necessarily everyone) via the recipient picker; "everyone live" is the default. One ciphertext serves the
whole subset.

## 4. Identity + contacts

Peers are shown by their advertised identity **handle**. You message a peer by selecting their identity
(Direct) or including them in a Broadcast subset. Saved **contacts** (name → address) and live peer
handles/`bot#id` all resolve through the same payment resolver, so chat and pay share one notion of "who".

## 5. In-chat commands

Backslash-prefixed; they travel as ordinary (encrypted) chat messages and are parsed on both sides. They
work player↔player AND player↔bot — pay is pay.

| Command | Effect |
|---------|--------|
| `\help` | List the commands. |
| `\address` | Ask the other party for an address; their client AUTO-replies a FRESH receive address (`\addr <a>`). |
| `\addr <address>` | State an address (your fresh receive sub-key). |
| `\pay <address \| handle \| bot#id \| contact> <sat>` | Make a real on-chain payment (SPV-signed, broadcast + IP-to-IP). |
| `\request <sat>` | Ask to be paid; posts a fresh address + amount. |
| `\balance` | Show your balance. |

The asker→responder flow ("Alice asks Bob where to send; Bob states an address; Alice pays") is exactly:
`\address` → peer auto-`\addr <a>` → `\pay <a> <sat>`.

## 6. Messenger features

History, replies, reactions, edits, deletes, and read receipts are supported (`Messenger` /
`Conversation`), rendered in the chat view; right-click a message for reply/react and (your own)
edit/delete.

## 7. Security boundary

- Content is always ciphertext on the wire; non-recipients cannot read it.
- Keys are per-message (Direct) or per-leaf (Broadcast); no static reuse.
- Messages are transactions — they inherit the same IP-to-IP, on-chain-capable transport as payments.

---

*Part of the exhaustive ESTATES reference documentation; grows with the code.*
