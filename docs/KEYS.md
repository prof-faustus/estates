# ESTATES Keys — derivation & storage reference

Every key in ESTATES comes from one 32-byte seed via in-tree, BSV-native derivation. No BIP32/39/44, no
mnemonic. This document specifies the seed, the KeyRing, Type-42 derivation, address mapping, and at-rest
encryption.

---

## 1. The seed

A single 32-byte secret. Created by the wallet wizard (displayed for backup before the wallet exists) or
restored from a 64-hex backup. It is stored only inside the encrypted wallet file (§5). The entire key ring
is deterministic from the seed, so the only mutable state worth persisting is the next receive-index cursor.

## 2. KeyRing

`KeyRing(seed)` yields:

- **Identity (index 0):** `IdentityPriv()` / `IdentityPub()` — the base identity key. ECDH-derivation root.
  **Never** an address, signing-for-spend, or receive target. Fixed; never rotates.
- **Sub-keys (index ≥ 1):** `PrivAt(i)` / `PubAt(i)` — deterministic operational keys; the address space is
  a `long`, so it is effectively unlimited (billions → trillions).
- **NextReceive():** the next FRESH, never-before-used receive sub-key; advances the cursor so a key is
  never handed out twice.
- **MessagePriv/Pub(counterpartyPub, convId, seq):** per-message keys, ECDH-bound to the counterparty and
  advanced per message — a hash chain, so the key for message/transaction A is never that of B.

## 3. Type-42 derivation

`Type42.UniqueKey(seed, label)` derives a unique secp256k1 private key from the seed and a label via HMAC
(the "number-42" scheme). `DerivePrivate(seed, counterpartyPub, invoice)` / `DerivePublic(...)` derive a
shared sub-key by ECDH between your key and the counterparty's pubkey for a given invoice/label, so payer
and payee independently arrive at the same fresh sub-address per payment. A used / on-chain key is
spend-only: it may still be spent, but is never offered to receive again.

## 4. Addresses

An address is `Base58Check(version, RIPEMD160(SHA256(pubkey)))` (`Address.P2pkh`): mainnet version 0x00,
testnet/regtest 0x6f. Only sub-keys (index ≥ 1) become addresses; index 0 (identity) never does. The
Destinations tab lists each sub-key's path (`estates/wallet/<i>`), index, and address.

## 5. At-rest encryption (`WalletStore`)

File layout: `"ESTW"(4) ‖ salt(16) ‖ nonce(12) ‖ AES-256-GCM(seed, key = PBKDF2-SHA256(password, salt,
200 000 iters, 32), aad = salt)`. Wrong password or a tampered file → decrypt fails closed (returns null,
never reveals the seed). The derived key buffer is zeroed after use. The seed is only in memory after
unlock. `Save Copy` backs up this encrypted file; it still needs the password.

## 6. Banned / required

- **Banned:** Ed25519 and any non-secp256k1 curve; BIP32/39/44 and any BTC key-derivation lib; mnemonics.
- **Required:** secp256k1 (BSV curve) for all signatures; HMAC hash-chain sub-keys; Base58Check seed backup;
  FORKID sighash for spends (`SIGHASH_ALL | FORKID = 0x41`), low-S ECDSA.

## 7. Why this design

- One seed reproduces the whole ring → trivial backup/restore, minimal persisted state.
- Identity isolation: the root only does ECDH; compromise of any operational sub-key never exposes it.
- Fresh-per-payment sub-addresses → unlinkable receives; per-message keys → no key reuse across messages.

---

*Part of the exhaustive ESTATES reference documentation; grows with the code.*
