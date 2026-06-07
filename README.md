# ESTATES

A dealerless, on-chain, peer-to-peer property game on **BSV**, delivered as a single
native Windows application: **`estates.exe`** (C# / .NET, WPF). No web client, no
webview, no server, no relay, no installer, no command-line options — double-click to run.

- **Money is native satoshis** (no token). One code path serves `mainnet`, `testnet`,
  and `regtest`; the network is a config tag, never a branch.
- **The client is the node.** It speaks the BSV peer protocol itself; it never depends
  on an external node or RPC service.
- **Everything on-chain, typed.** Each transaction TYPE is its own documented protocol
  with a unique number and self-identifying header — see [`docs/PROTOCOLS.md`](docs/PROTOCOLS.md).
- **Title deeds, cards, and player identity are 1-sat encrypted NFTs**, moved by atomic
  transactions.
- **Provably-fair dice** via 2-party commit→reveal, publicly recomputable.
- **Non-custodial** per-seat keys; the wallet protects funds and never asks for money.
- **Original, non-copyright content only.**

## Cryptography & rules

- secp256k1 only; ECDSA (low-S, fresh CSPRNG nonce); ECDH-derived AES-256-GCM for
  encryption; BSV-native (Type-42 / hash-chained) key derivation; FORKID sighash.
- On-chain data is pushdata in live script (`OP_DROP`/`OP_2DROP`), not `OP_RETURN`.
- All timing is `nLockTime` (absolute) + `nSequence` (relative).
- Every parameter derives from [`params/estates.v1.json`](params/estates.v1.json).

See [`SECURITY.md`](SECURITY.md) for the security posture, including an explicit list of
what is **not yet done or proven** — no completion is claimed beyond stated evidence.

## Build & run

```
dotnet publish apps/native/Estates.App -c Release -r win-x64 --self-contained true ^
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

The self-contained `estates.exe` is produced under the publish output and copied to the
repository root. Run it by double-clicking; there are no launch options.

## Verify

```
dotnet run --project apps/native/Estates.Conformance -c Release
```

Prints the conformance pass/fail count (positive + hostile-negative assertions over the
crypto core, typed-transaction suite, messenger, node-wallet balance logic, and miner
supervisor). That printed count is the only verification evidence claimed.
