# ESTATES — build status (honest, per-phase)

Overall ≈ **15%** against the A++ / 1000-build / 1M-doc bar. NOT finished; nothing is "done" until you
confirm each tab works at runtime.

| Phase | % | State |
|-------|---|-------|
| Identity (Base ID / Type-42 / HMAC hash-chain, integrated) | ~70% | code + tests; base ID never an address; needs deeper game wiring + node-verified pays |
| SPV money (envelope / merkle proof / headers / Bloom BIP37) | ~55% | code + tests; not runtime-verified end-to-end; node-proof flow partial |
| ElectrumSVP wallet UI (dark tabs + all features) | ~40% | shell + full tab set + tables structurally there; not A++-polished; no tab confirmed by you |
| QR | ~80% | real in-tree encoder (RS GF(256), 40 versions, byte mode, masks), verified, rendered in Receive; scan still to do |
| Multisig / vaults | ~25% | 2-of-2 spend primitive done; vault UI + mandatory nLockTime recovery + node-proof to do |
| NFTs | ~30% | display + local mint/transfer/persist; on-chain mint + transfer as real txs to do |
| Chat / game integration | ~40% | chat uses identity + contacts; game seats not yet @handle/pay-from-game |
| Smart agent | ~20% | command agent works; far from "smart" |
| Documentation (1M target) | <1% | 10 reference doc files |
| Runtime / node acceptance | 0% | no tab confirmed by you yet |

## Steps to go
1. Vault UI with **mandatory nLockTime recovery** — consensus-critical, built node-verified, not rushed.
2. On-chain NFT **mint + transfer** to an identity (real txs, TxType.NftMint/Transfer).
3. Game seats show **@handle** + pay/message from the game.
4. Richer transaction dialog + History right-click parity; multi-account.
5. QR **scan** (Send / BIP270).
6. Network / Preferences dialogs (servers, explorers).
7. Massive documentation toward the 1M target.
8. Per-tab tests + a runtime verification pass with you.

Next: ② on-chain NFT + ③ game wiring, then ① vaults carefully.
