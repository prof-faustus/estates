# ESTATES Identity — reference

Identity in ESTATES is a first-class, cryptographic object: a persistent **handle** bound to a **base
identity key**, used to pay, chat, and play as one identity, and rendered as an NFT card. This document
specifies the key architecture, the handle, resolution, and the links to chat / NFTs / the game.

---

## 1. The base identity key (index 0)

The wallet seed (32 bytes, encrypted at rest) derives, via the in-tree `KeyRing`, a reserved
**index-0 base identity key** (`IdentityPriv` / `IdentityPub`). This key is the cryptographic root of the
player's identity.

**Absolute rule:** the base identity key is used **only** to root ECDH derivation. It is **never** a
receive address, **never** a change address, **never** a P2PKH output on chain, and **never** offered to be
paid. Using index 0 as an address is rejected.

WHY: keeping the root off-chain and non-spendable means that observing or compromising any operational
sub-key cannot expose or de-anonymise the identity root. The root participates only in key agreement.

## 2. Operational sub-keys (index ≥ 1, HMAC hash-chain)

Every address, change output, and signing key is a sub-key at index ≥ 1, derived through the Type-42 / HMAC
hash-chain (`KeyRing.PrivAt`, `NextReceive`, `Type42`). Per-conversation message keys are ECDH-bound to the
counterparty and advance per message, so no key is reused across transactions or messages. Receiving always
hands out a fresh, never-before-used sub-key.

## 3. The handle

A human-readable name (e.g. "Bob") bound to the identity. It is:

- **Persistent** — stored at `%APPDATA%/Estates/identity.txt`, loaded at login.
- **Advertised** — set as the node's announce name, so live peers see the handle.
- **Editable** — in the Identity tab (and the chat identity row); saving re-advertises it.

The handle is a convenience label over the identity key; the key is the cryptographic truth.

## 4. Resolution — pay/chat by identity (pay is pay)

A single resolver (`ResolveAddress`) maps a recipient token to an address, used by Send and the chat
`\pay` command identically:

1. a literal Base58Check P2PKH **address**; else
2. a live peer's advertised **handle** or **bot#id** → that peer's advertised receive address; else
3. a saved **contact** name → its stored address.

So `\pay Bob 1000`, `\pay bot#3 1000`, `\pay <address> 1000`, and `\pay <contact> 1000` all work through
one path. There is no per-target payment method.

## 5. Identity ↔ chat

Chat is identity-addressed:

- **Direct** — two-person secp256k1 ECDH to one identity (`TxType.Chat2P`).
- **Broadcast** — the GB 2623780 B key-graph (broadcast encryption) to a **chosen subset** of identities
  (one ciphertext only that subset can open), or everyone live.
- Commands (`\help`, `\address`, `\addr`, `\pay`, `\request`, `\balance`) work player↔player and
  player↔bot; `\address` auto-replies a fresh receive address.

Every chat message travels as a BSV transaction (carrier output), IP-to-IP.

## 6. Identity ↔ NFTs

The identity is the owner of all NFTs and is itself rendered as an **identity NFT card** (handle + identity
key) in the NFTs tab. Deeds / game cards are shown as owned by the identity. The identity card links the
player's games and history.

## 7. Identity ↔ game

A player joins and plays the game as their identity. Funds, deeds, and chat all key off the same identity,
so a player is one coherent on-chain entity across wallet, chat, and game.

## 8. Security boundary

- The base identity key never appears on chain and is never a spend/receive target.
- Sub-keys are deterministic from the seed; the only state worth persisting is the next-index cursor.
- The seed (hence every key) is encrypted at rest (AES-256-GCM + PBKDF2-SHA256); wrong password fails
  closed. Losing the seed loses the identity and funds — the creation wizard forces a seed backup.

---

*Part of the exhaustive ESTATES reference documentation; grows with the code.*
