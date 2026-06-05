# ESTATES — native Windows client (`estates.exe`)

A **true native Windows** ESTATES client: C# / .NET 8 **WPF**, no webview, no Tauri,
no embedded browser. It double-clicks to a real window and runs the **same audited
game** the web app runs — proven *byte-for-byte*, not by resemblance.

There are two ESTATES deliverables and this is one of them:

- **`estates.exe`** — this native app (self-contained single file; no runtime to install).
- **the web app** — `apps/client-web` (see the repo root README).

Both speak the identical wire protocol and the identical canonical state machine, so
a native client and a browser client can sit at the same table.

---

## Why a separate native core, and why it is *not* a fork

The game's rules, crypto, consensus hashing and message authentication are defined
**once**, in the audited TypeScript packages (`packages/*`). The native app does **not**
re-invent them — it ports them and then **cross-validates every port against the
TypeScript reference** using machine-generated vectors. A divergence of a single byte
fails the build. So "native" here means *a second independent implementation that is
provably equal to the reference*, which is exactly what you want for an auditable system
(two implementations, one specification, mechanically checked agreement).

### Projects

| Project | What it is |
| --- | --- |
| `Estates.Core` | The native engine + crypto + consensus: `Engine` (rules), `Canonical` (state hash), `Tx`/`Scriptvm` (BIP-143 sighash + secp256k1 ECDSA), `Sign` (HKDF→Ed25519 per-game identity), `KeyLife` (one-game key manifest verify), `Beacon` (dealerless commit/reveal dice), `CardNftN` (1-sat card NFT mint/transfer/verify), `TableMsg` (canonical signed-frame bytes + verify), `RelayClient` (HTTP relay), `GameReplay` (replay an ordered relay log to canonical state). |
| `Estates.App` | The WPF window (`estates.exe`): renders the board from `estates.v1.json`, runs a deterministic local demo game, and **spectates a LIVE game over the relay** (reads the channel, replays it, shows seats/balances/positions/phase/turn + the canonical state hash). |
| `Estates.Conformance` | A console runner that loads the TS-emitted vectors and asserts the native code reproduces them exactly, layer by layer. Its exit code gates all of them to zero failures. |

---

## Build the single-file `estates.exe`

Needs the .NET 8 SDK (the host install lives at `D:\dotnet`).

```powershell
$env:PATH = "D:\dotnet;$env:PATH"; $env:DOTNET_CLI_HOME = "$env:TEMP\dh"
dotnet publish apps/native/Estates.App -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
# result: apps/native/Estates.App/bin/Release/net8.0-windows/win-x64/publish/estates.exe
# a copy is kept at the repo root as estates.exe
```

`estates.exe` is self-contained: it bundles the .NET runtime, so the target machine needs
nothing pre-installed. Double-click it — there are **zero** command-line options.

---

## Prove the native client equals the web (the parity gate)

Every native layer is cross-validated against the TypeScript reference. The vectors are
regenerated from the audited TS by `tools/*-vectors.ts`, then checked by the conformance
runner:

```bash
# (re)generate the cross-validation vectors from the audited TS reference
for v in keylife tx cardnft scriptvm sign tablemsg beacon frames replay; do
  node --experimental-strip-types tools/$v-vectors.ts
done

# run every native layer against them
cd apps/native/Estates.Conformance && dotnet run -c Release
```

Layers checked: engine rules, canonical state hash, tx serialization + txid, card-NFT
output/transfer, BIP-143 sighash + ECDSA verify, key derivation + Ed25519, every signed
table-message kind, dice beacon, and a full-game **replay** (an ordered relay log replays
to the *same* canonical hash as the web NetTable).

### Live HTTP spectate — the read path over the real wire

Beyond the static replay vector, the native spectate path is proven against a **live HTTP
relay carrying a real game**:

```bash
pnpm proof:native      # needs the .NET SDK on PATH (or at D:\dotnet)
```

This (1) starts the real HTTP relay, (2) drives a real two-peer `NetTable` game over it,
(3) builds + runs `Estates.Conformance` pointed at that live channel, so the **native
`RelayClient` reads the frames back over HTTP and `GameReplay` replays them to the exact
canonical state hash the web produced**, then (4) shuts the relay down (no leftover
processes). The conformance prints:

```
Estates.Conformance (spectate): PASS — native read N frames live over HTTP from '<channel>'
and replayed to the SAME hash as the web (<hash>…)
```

You can also run just the live relay+game and point the running `estates.exe` at it:

```bash
RELAY_PORT=8799 RELAY_CHANNEL=demo pnpm spectate:relay   # leaves a relay running on :8799
```

then in `estates.exe`: set **relay** = `http://127.0.0.1:8799`, **game** = `demo`, press
**Spectate**. The window polls the channel every 2s and shows the live, fully-authenticated
state. (Every frame is Ed25519-verified against its seat key before it can affect state;
raw dice are dropped — dice come only from the dealerless beacon.)

---

## What "native" buys, security-wise

- **A second, independent implementation of the consensus rules**, mechanically held equal
  to the reference. A rule bug that slipped past one implementation has to also exist,
  identically, in the other — and the vectors would catch the disagreement.
- **No webview attack surface.** The native client is not a browser; there is no embedded
  Chromium/WebView2, no JS bridge, no remote content.
- **The same authentication everywhere.** The native `GameReplay` authenticates every relay
  frame exactly as the web does (per-game Ed25519 seat keys, canonical signed bytes), so a
  native spectator cannot be fed a forged or replayed frame.
