# DECISIONS.md — ESTATES

Phase-0 decisions per the BUILD-KICKOFF. Each is the recorded v1 choice and is
**overridable by the author** (change here + re-run conformance vectors).

| ID | Decision | v1 choice | Rationale / override |
|---|---|---|---|
| **D-CORE** | One deterministic core vs two cross-checked | **TypeScript core** is authoritative for client + tests; the Go service is a **verifier** re-executing the same conformance vectors. | Single core avoids divergence risk; Go cross-check guards it. Override → second WASM core (O5). |
| **D-ENFORCE** | Rule legality in-Script vs core+transcript | **v1:** custody / value-conservation / atomicity enforced **in Script**; full rule legality is **publicly verifiable via transcript**, not all Script-enforced. | Add in-script predicates later only for concrete justified cheat vectors. |
| **D-MORTGAGE** | Mortgage representation | **Flag on the title NFT** (`mortgaged` field flips in live script), not a custody transfer. | Keeps ownership stable; simpler provenance. |
| **D-BUILD** | House/estate representation | **State carried on the title NFT, re-minted on change** (`build_level` 0–5); even-build enforced by core + peer validation. | Override → separate building tokens. |
| **D-AUCTION** | Auction format | **Sealed-bid commit→reveal** (reuses C4/C6). | Override → open ascending-bid. |
| **D-BANK** | Optional dispute path | **OFF by default.** Optional `2-of-3` dispute path w/ named third party for high-stakes tables (reintroduces a trusted party — listed in trust surface). | Off keeps trustlessness; opt-in per table. |
| **D-BANK-ENFORCE** | Bank guard without an operator | **v1: `M-of-N` threshold over seats + core validation** (trust = honest quorum, stated). | **Upgrade:** covenant via sighash-preimage introspection (BSVM/sCrypt) — removes quorum assumption; scheduled, not a v1 gate. |
| **D-UI** | Board rendering | **SVG** (follow `frontend-design` skill). | Override → Canvas/WebGL. |
| **D-PACKAGE** | Packaging | **Web first**; Tauri desktop optional (confirm before building). | — |
| **D-WIN** | Win condition | **Last solvent seat**, OR **highest total worth** at an agreed turn/time cap. | Worth = sats + unmortgaged build value + mortgage values of mortgaged props. |
| **D-RENT-CLAIM** | Rent active vs auto | **Auto-claim by core at landing** (rent cannot be evaded by inattention). | Override → must-claim window. |
| **D-TRADE-OOB** | Out-of-turn trades | **Allowed by default**; always atomic, never one-sided. | Override → in-turn only. |
| **D-BUILD-SUPPLY** | House/estate scarcity | **Finite: 32 houses, 12 estates** (enforced). | Override → unlimited. |
| **D-RESERVE** | Bank reserve sizing | Size at setup to **cover salaries for the configured turn/time cap**, or fund from a portion of buy-ins. On **regtest, auto-funded** (explicit, logged). | Concrete figure set at table genesis from `estates.v1.json`. |

## Trust surface (v1)

1. **Bank honest quorum** (D-BANK-ENFORCE M-of-N) — removed by the covenant upgrade.
2. **Optional named third party** only if D-BANK is switched ON for a table (off by default).
3. **Relay** is untrusted (opaque fan-out); canonical truth is the indexer/chain projection.

All other paths (dice, custody, trades, NFT provenance) are trustless by construction.
