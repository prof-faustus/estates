# Runbook: live on-chain (regtest / testnet / mainnet)

`@estates/wallet` builds, BIP-143-signs, and broadcasts **real BSV transactions**.
Networks differ only in addresses + how you broadcast.

## regtest (local, free) — VERIFIED

This round-trip was run live and confirmed on a regtest node:

1. Stand up a regtest BSV node (in the VM), e.g. `bitcoinsv/bitcoin-sv:1.1.0`:
   ```
   docker run -d --name estates-bsv -p 18443:18332 bitcoinsv/bitcoin-sv:1.1.0 \
     bitcoind -regtest=1 -rpcuser=e -rpcpassword=e -rpcbind=0.0.0.0 \
     -rpcallowip=0.0.0.0/0 -rpcport=18332 -server=1 -listen=0 \
     -fallbackfee=0.00001 -minminingtxfee=0.00000500
   ```
2. Mature coins + fund a wallet address:
   ```
   bitcoin-cli ... createwallet e
   bitcoin-cli ... generatetoaddress 101 <node-addr>
   bitcoin-cli ... sendtoaddress <ESTATES-wallet-addr> 1.0
   bitcoin-cli ... generatetoaddress 1 <node-addr>      # confirm the funding
   ```
3. Build + sign + broadcast from the wallet:
   ```ts
   const wallet = Wallet.fromWif(wif, 'regtest');
   const { hex } = await wallet.buildAndSign(
     [{ sourceTxHex, vout, satoshis }],
     [{ address: payee, satoshis: 50_000_000 }],
   );
   await wallet.broadcast(hex, { rpcUrl: 'http://127.0.0.1:18443', rpcUser: 'e', rpcPass: 'e' });
   ```
   The node accepts `sendrawtransaction`; mine 1 block and the spend confirms.

> **Verified result:** funded 1 BSV → built + signed a 0.5 BSV spend (+ change) →
> the node accepted the broadcast and mined it; the 0.5 BSV output is on-chain.
> The node runs in the VM (host stays clean). Use port 18443 if 18332 is taken.

## testnet (live, free coins)

1. Fund the wallet address from a BSV **testnet faucet**.
2. Fetch a UTXO's source-tx hex (e.g. WhatsOnChain `/tx/hash/{txid}/hex`).
3. `Wallet.fromWif(wif, 'testnet')` → `buildAndSign(...)` → `broadcast(hex)`
   (goes to WhatsOnChain `test`). No RPC needed.

## mainnet (REAL VALUE)

Identical, but `broadcast` **refuses to send without `confirmRealValue: true`** —
a deliberate money guard. Only pass it when you intend to spend real satoshis.
