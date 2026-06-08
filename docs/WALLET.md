# ESTATES Wallet — reference documentation

The ESTATES wallet is a standalone, in-process BSV **SPV wallet** built into `estates.exe`. It is
modelled on ElectrumSV's structure (menu bar, status bar, tabbed list/table views) and extended with an
**identity** layer, **NFT** integration, **chat-by-identity**, and **Craig's SPV** (IP-to-IP envelope
delivery + Bloom-filter address matching). This document describes every component: WHAT it is, HOW it
works, and WHY it is built that way.

> Scope note: this is the wallet reference. The estate node, gossip overlay, chat, bots, and game are
> documented separately. Nothing here contacts a central server — ESTATES is pure peer-to-peer.

---

## 1. Key architecture (the foundation)

### 1.1 Base identity key — index 0, ECDH-derivation only, NEVER an address
The wallet is derived from a single 32-byte seed (`WalletStore`, AES-256-GCM encrypted at rest under a
PBKDF2-SHA256(200 000) password). From that seed the in-tree `KeyRing` derives keys:

- **Index 0 = the base IDENTITY key** (`KeyRing.IdentityPriv`/`IdentityPub`). It is the cryptographic
  root of identity and the partner in ECDH derivations. **It is never used as a receive address, never a
  change address, never appears on chain as a P2PKH output.** Treating index 0 as an address is rejected.
- **Index ≥ 1 = operational sub-keys** (`KeyRing.PrivAt(i)`/`PubAt(i)`, `NextReceive()`). Every receive
  address, change address and signing key is one of these HMAC hash-chain sub-keys.

WHY: isolating the base identity means observing or spending any operational sub-key never exposes the
root. The root only ever participates in ECDH; it is never a spend/receive target.

### 1.2 HMAC hash-chain sub-keys (Type-42)
Sub-keys are produced by the in-tree Type-42 / HMAC derivation (`Type42.UniqueKey`, `DerivePrivate`,
`DerivePublic`). Per-message keys are ECDH-bound to the counterparty and advance per message (a hash
chain), so the key for transaction A is never the key for transaction B. BIP32/39/44 are **not** used;
the seed is backed up as raw hex / Base58Check, never as a BIP39 mnemonic.

### 1.3 Fresh address per payment
The Receive tab and the chat `\address` flow hand out a **fresh, never-before-used** sub-key address each
time (`NextRecvAddress`). A used / on-chain key is spend-only: the wallet may still spend it, but it is
never offered to receive again.

---

## 2. SPV (Craig's SPV — not BTC SPV)

A coin is delivered as an **envelope**: the raw transaction + its merkle proof (`branch`, `index`) + the
80-byte block header that proves it was mined (`SpvEnvelope`). The sender stores that envelope and hands
it to the payee **IP-to-IP** with the payment. The receiving wallet (`SpvWallet`):

1. **Verifies** the envelope — the merkle branch reaches the header's merkle root AND the header meets its
   stated proof-of-work (`SpvEnvelope.Verify` → `MerkleProof.Verify` + `BsvHeaders.MeetsProofOfWork`).
2. **Stores** it — always — so the coin's proof can be handed to the next payee.
3. **Credits** any outputs paying the wallet's owned scripts.

There is no chain scan and no header IBD: the proof arrives with the money. A BSV node is used only as a
*proof source* (to fetch proofs for coins paid to the wallet's own addresses on bring-up); live play
delivers envelopes directly between peers. The wallet is always online.

### 2.1 Bloom filter (BIP37)
`BloomFilter` is an in-tree BIP37 filter (MurmurHash3 x86_32). The wallet inserts its watched
address/script hashes, so a serving peer can be told *which* outputs to match without revealing the exact
set. No false negatives; a tunable false-positive rate. `FilterLoad()` produces the wire payload
(`varint(len)‖data‖nHashFuncs‖nTweak‖nFlags`). Shown live in the Network/SPV tab.

---

## 3. The wallet window — shell

Ported from ElectrumSV's `main_window`:

- **Menu bar:** File (Open, New/Restore, Save Copy, Quit) · Wallet (Information, Password, Contacts›New,
  Find) · View (toggle every tab) · Tools (Preferences, Network, Sign/verify, Encrypt/decrypt, Pay to
  many, Sweep Private Key, Load transaction › text/blockchain/QR) · Help (About, Website).
- **Status bar:** live balance · network · "SPV (IP-to-IP + Bloom)" · 🔒 encrypted.
- **Network selector** (mainnet/testnet/regtest) in the global header; regtest is password-gated.

---

## 4. Tabs

| Tab | What it shows / does |
|-----|----------------------|
| **Info** | Network, three balances (spendable / pending / immature), On-chain (SPV) balance, recovery seed, identity key (index 0, labelled never-an-address), receive address #1, lock. |
| **Fund** | Your receive address (a sub-key, index ≥ 1) to be PAID — funding is always a real on-chain payment, never an import. |
| **Send** | Pay-to-many (one recipient per line: address / identity-handle / bot#id / contact + sat), fee in **sat/kB**, coin control (frozen coins excluded), SPV-signed, broadcast to node + IP-to-IP. |
| **Receive** | A fresh sub-key address per request, requested amount, copy, and a `bitcoin:` payment-request URI. |
| **History** | A sortable table: received coins (via SPV proof) + this session's sends/invoices, newest first. |
| **Coins** | Every UTXO as a table (Value / Frozen / Address / Outpoint); double-click toggles freeze (coin control). |
| **Destinations** | Addresses with derivation paths (index ≥ 1); index 0 (identity) is never listed as an address. |
| **Coinsplit** | Split the balance into N fresh UTXOs (fixed or randomized). |
| **Contacts** | Named payees (name + address) you can pay by name in Send/chat. |
| **Identity** | Set/save a persistent identity handle (advertised so peers find/chat/pay you by identity); shows the identity key and how it's used to pay/chat/play. |
| **NFTs** | Visual cards: your IDENTITY NFT card (handle + identity key) plus deed/game cards owned by your identity. |
| **Network** | Craig's SPV model + the live BIP37 Bloom filter parameters (size, hash funcs, tweak, filterload bytes). |
| **Tools** | Sign/verify message (secp256k1 ECDSA), encrypt/decrypt (ECDH), sweep a private key (raw 64-hex or BIP38 `6P…` + passphrase), BIP270 invoice pay (Anypay/Centi URL or `bitcoin:` URI), load/broadcast a raw tx. |
| **Console** | Type in-wallet commands (`\help`, `\address`, `\balance`). |

---

## 5. Pay is pay (one payment path)

There is no per-target payment method (no "fund a bot"). A single resolver (`ResolveAddress`) maps a
recipient token to an address:

1. a literal address (Base58Check P2PKH), or
2. a live peer's advertised identity **handle** or **bot#id** → that peer's advertised receive address, or
3. a saved **contact** name → its address.

Send and the chat `\pay <recipient> <sat>` command both use this resolver, so paying a player, a bot, a
contact, or an identity is identical.

---

## 6. Identity, NFTs, chat, game — linkage

- **Identity** is your handle bound to the base identity key. It is advertised over the node announce, so
  peers can find, chat to, and pay you by identity.
- **NFTs** are owned by the identity. The identity itself is rendered as an NFT card; deeds/game cards are
  shown as owned by the identity.
- **Chat** uses the identity: Direct (two-person secp256k1 ECDH to one identity) or Broadcast (the
  GB 2623780 B key-graph to a chosen subset). The `\address`/`\pay` commands work player↔player and
  player↔bot.
- **Game** play is as the identity; deeds won/bought land in the NFT tab owned by the identity.

---

## 7. BIP38 / sweep

`Bip38.Decrypt` decodes a no-EC-multiply `6P…` key: scrypt(passphrase, addresshash, 16384, 8, 8, 64) →
two halves, AES-256-ECB decrypt of the two 16-byte blocks, XOR with the first half → the 32-byte key,
verified by re-deriving the address. `Scrypt` (RFC 7914: Salsa20/8 → BlockMix → ROMix) is in-tree and
verified against the canonical `TestingOneTwoThree` vector. Sweep then builds + signs a tx moving the
key's coins into the wallet.

---

## 8. Money safety

- Keys encrypted at rest (AES-256-GCM + PBKDF2-SHA256). Wrong password fails closed.
- The existing wallet/seed is preserved across rebuilds; replacing it requires an explicit typed `REPLACE`.
- Bots refund the funder 100% on close; when the human closes, bots close + refund first.

---

*This document is part of the exhaustive ESTATES reference documentation and grows with the code.*
