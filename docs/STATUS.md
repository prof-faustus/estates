# ESTATES — build status & steps to go

Honest state: this is scaffolding toward an A++ target (ElectrumSVP is the C- baseline to exceed). NOT
finished. Below: what is in vs the major work remaining.

## In so far (wallet)
- [x] Key arch: base identity key = index 0, ECDH-root, NEVER an address; addresses = HMAC sub-keys (≥1)
- [x] Keys encrypted at rest (AES-256-GCM + PBKDF2-SHA256); Save Copy backup; Password change
- [x] Wallet-create wizard step: seed generated → displayed → confirmed → persisted (existing wallet kept)
- [x] ElectrumSV shell: menu bar (File/Wallet/View/Tools/Help) + status bar
- [x] Tabs: Info · Fund · Send · Receive · Requests · History · Transactions · Coins · Destinations ·
      Coinsplit · Contacts · Identity · NFTs · Network · Tools · Console · Notifications
- [x] Tables (DataGrid) for History/Coins/Destinations/Contacts/Transactions/Notifications/Requests
- [x] Send: pay-to-many, fee sat/kB, coin control (freeze), pay-is-pay resolver
- [x] Receive: fresh sub-key per request (cursor persisted), amount, URI, save request
- [x] Sweep (raw + BIP38/scrypt, verified), sign/verify, encrypt/decrypt, load/decode/broadcast tx, BIP270
- [x] Bloom filter (BIP37) + Network/SPV tab; Craig's SPV (IP-to-IP envelopes)
- [x] Identity tab + persistent advertised handle; NFTs (mint/transfer/persist, owned by identity)
- [x] Contacts/NFTs/requests/network/cursor persisted across restarts
- [x] Reference docs: ARCHITECTURE, WALLET, SPV, IDENTITY, KEYS, CHAT, BOTS, GAME, TRANSPORT (+ index)

## Steps to go (major)
- [ ] Full multi-screen wizard (account types, restore flows, cosigner) — currently one step
- [ ] Table parity: per-row labels, right-click actions, sorting/columns to ElectrumSV depth
- [ ] Address/transaction LABELS (editable, persisted) across History/Coins/Destinations
- [ ] Unit selector (Bitcoin/BSV/mBSV) applied everywhere; fiat
- [ ] On-chain NFT mint/transfer as real txs (TxType.NftMint/Transfer), not local-only records
- [ ] QR: generate (Receive) + scan (Send/BIP270)
- [ ] Network dialog/preferences screens (servers, explorers) ported
- [ ] Deeper identity↔chat↔game integration; in-game NFT deeds as on-chain NFTs
- [ ] Built-in smart agent
- [ ] Exhaustive documentation toward the million-line target
- [ ] Conformance/tests expanded to every claim; thousands of build iterations

## Where I'm at
Early. The shell + full tab inventory + core features + key architecture + persistence + first docs are in
and building green each iteration. The depth (labels, units, full wizard, on-chain NFTs, smart agent, the
million-line docs, table parity) is the bulk still ahead.
