# @estates/wallet — security boundary

Reference cryptographic infrastructure: a **real BSV wallet on the project's own
@noble crypto** — no external SDK. Written so an auditor can attack it.

## What this package is

Everything native and isomorphic (Node + the desktop webview):
- secp256k1 keys, **WIF** (base58check), **P2PKH** addresses (network-versioned),
- **real BIP-143-signed P2PKH transactions** (`@estates/tx` serialization),
- broadcast via your **own node's** JSON-RPC (regtest) or a testnet/mainnet endpoint,
- **money guards**: mainnet broadcast is refused without an explicit confirmation;
  regtest needs an RPC url.

No external dependency on purpose: `@bsv/sdk` shipped circular ESM that broke the
production bundle, and an external repo would violate the standalone rule.

## The properties this exists to guarantee

> 1. Addresses/keys are correct and reversible (WIF round-trips; correct network
>    version bytes).
> 2. A signed transaction is genuinely script-valid (self-verified before broadcast).
> 3. No value is stranded on a refund; no accidental mainnet spend.

- **Correct key material:** mainnet vs testnet addresses carry the right version
  bytes; `fromWif` round-trips to the same address + private key.
- **Self-verifying signatures:** after signing a BIP-143 P2PKH tx the wallet runs it
  through `@estates/scriptvm` (`verifyTx`) and asserts it is script-valid — a
  malformed signature/sighash is caught before broadcast.
- **Full refund:** `drainTo` refunds the entire balance minus fee to a single
  address — nothing is left stranded (this conservation property also backs the bot
  rule that a sim player returns 100% of funds to its funder on close).
- **Money guards:** mainnet (real value) is refused unless the caller explicitly
  confirms; regtest requires an RPC url. An accidental real-value spend is blocked by
  construction.

## Threat model

- A tampered or wrong-key signature slips through → the pre-broadcast self-verify
  (`verifyTx`) rejects it.
- A refund/drain leaves dust or strands balance → `drainTo` sends the full balance
  minus fee to one address.
- An accidental mainnet broadcast → refused without explicit `confirmRealValue`.
- A malformed WIF/address/hex → rejected (base58check + hex validation).

## What this package does NOT do

- It does not derive one-use per-output keys (that is `@estates/keys` BRC-42) and
  does not define the NFT/script encodings (`@estates/onchain`). It holds the master
  key and produces/signs/broadcasts real transactions.
