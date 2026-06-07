# ESTATES — security posture

ESTATES is a native Windows application (`estates.exe`, C# / .NET, WPF). There is no
web client, no webview, no server, no relay, and no developer/command-line product
path. The client is a peer in a true peer-to-peer system.

This document states what is **implemented and verified**, and — explicitly — what is
**not yet done or not yet proven**. No claim of "complete", "production ready", or
"CI green" is made beyond the exact evidence below.

## Cryptography (in-tree, no third-party library)

All cryptography is implemented in-tree over the Microsoft .NET base class library only
(`System.Numerics`, `System.Security.Cryptography`). No external crypto library is used.

- **Curve:** secp256k1 only (the BSV curve). No other signature curve appears anywhere
  in the codebase.
- **Signatures:** ECDSA on secp256k1, low-S, with a fresh CSPRNG-drawn random nonce per
  signature (rejection-sampled in `[1, n-1]`).
- **Encryption:** ECDH-derived shared secret used directly as an AES-256-GCM key. No
  ephemeral-key / KDF hybrid scheme is used.
- **Key derivation:** BSV-native Type-42 / hash-chained derivation from one 32-byte seed.
  No hierarchical-wallet standard and no mnemonic scheme.
- **Sighash:** the BSV FORKID sighash (`SIGHASH_ALL | FORKID`).

## What is verified

The `Estates.Conformance` project runs positive and hostile-negative assertions over the
crypto core, the typed-transaction protocol suite, the messenger model, the node-backed
wallet balance logic, and the in-process miner supervisor. Run it with:

```
dotnet run --project apps/native/Estates.Conformance -c Release
```

It prints the pass/fail count. Treat that printed count as the only verification
evidence — do not infer anything beyond it.

## What is NOT done / not yet proven (honest)

- The wallet shown in the running exe is being migrated to a real node-backed wallet
  (`NodeWallet`) that reads balances (immature / unconfirmed / spendable) from the chain
  the client connects to. Until that wiring lands, the wallet does not reflect live chain
  state. This is tracked, not finished.
- Full Bitcoin **script-satisfaction** (locking-script execution) for every spend path is
  not yet implemented end-to-end.
- The in-process miner supervisor performs real proof-of-work and self-heals workers, but
  is not yet wired to pull real block templates and submit found blocks.
- No third-party security audit has been completed against this native codebase.

## Reporting

This is open reference cryptographic infrastructure intended for hostile review. Security
issues and design questions should be raised as repository issues.
