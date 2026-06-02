/**
 * @estates/cli core — create a REAL on-chain table on a chosen network.
 *
 * A table genesis is one real BSV tx that funds each seat's starting balance
 * (native sats) and a bank COVENANT reserve output (D-BANK-ENFORCE: spendable
 * only by a rules-legal payout — no trusted banker). The network is the user's
 * choice: a regtest node (JSON-RPC), testnet, or mainnet (guarded).
 */
import { Transaction, P2PKH, LockingScript } from '@bsv/sdk';
import { loadParams } from '@estates/params';
import { covenantOutput, rulesHash } from '@estates/bank';
import { Wallet, rpcBroadcast, type Network } from '@estates/wallet';

const P = loadParams();
const bytesToHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

export interface NodeRpc { url: string; user: string; pass: string; }

/** Minimal JSON-RPC call to a regtest/local node. */
export async function rpc(node: NodeRpc, method: string, params: unknown[] = []): Promise<unknown> {
  const res = await fetch(node.url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Basic ' + Buffer.from(`${node.user}:${node.pass}`).toString('base64') },
    body: JSON.stringify({ jsonrpc: '1.0', id: 'estates', method, params }),
  });
  const j = (await res.json()) as { result?: unknown; error?: { message: string } };
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}

export interface Funding { txid: string; vout: number; satoshis: number; raw: string; }

/** Fund `address` from a regtest node's default wallet; return the new UTXO. */
export async function nodeFund(node: NodeRpc, address: string, amountBsv: number): Promise<Funding> {
  const mine = (await rpc(node, 'getnewaddress')) as string;
  await rpc(node, 'generatetoaddress', [101, mine]);              // ensure mature coins
  const txid = (await rpc(node, 'sendtoaddress', [address, amountBsv])) as string;
  await rpc(node, 'generatetoaddress', [1, mine]);                // confirm the funding
  const raw = (await rpc(node, 'getrawtransaction', [txid])) as string;
  const verbose = (await rpc(node, 'getrawtransaction', [txid, 1])) as { vout: { n: number; value: number; scriptPubKey: { addresses?: string[]; address?: string } }[] };
  for (const o of verbose.vout) {
    const addrs = o.scriptPubKey.addresses ?? (o.scriptPubKey.address ? [o.scriptPubKey.address] : []);
    if (addrs.includes(address)) return { txid, vout: o.n, satoshis: Math.round(o.value * 1e8), raw };
  }
  throw new Error('funding output to the funder address not found');
}

export interface TableSeat { wif: string; address: string; startingBalance: number; }
export interface TableTx {
  network: Network;
  hex: string;
  genesisTxid: string;
  seats: TableSeat[];
  reserve: { satoshis: number; vout: number };
}
export interface TableResult extends TableTx { broadcast: { txid: string }; }

export interface TableOpts {
  network: Network;
  funder: Wallet;
  funding: Funding;
  seatCount: number;
  reserveSalaryCap?: number;
  node?: NodeRpc;
  confirmRealValue?: boolean;
}

/**
 * Build + sign (BIP-143) the table genesis tx: `seatCount` P2PKH seat outputs
 * (starting balance each) + a covenant reserve output + change. No broadcast.
 */
export async function buildTableTx(opts: TableOpts): Promise<TableTx> {
  const startingBalance = P.scalars.starting_balance_per_seat;
  const reserve = P.scalars.salary * (opts.reserveSalaryCap ?? 200);

  const seats: TableSeat[] = [];
  const tx = new Transaction();
  tx.addInput({
    sourceTransaction: Transaction.fromHex(opts.funding.raw),
    sourceOutputIndex: opts.funding.vout,
    unlockingScriptTemplate: new P2PKH().unlock(opts.funder.key),
  });
  for (let i = 0; i < opts.seatCount; i++) {
    const w = Wallet.random(opts.network);
    seats.push({ wif: w.key.toWif(), address: w.address, startingBalance });
    tx.addOutput({ lockingScript: new P2PKH().lock(w.address), satoshis: startingBalance });
  }
  const covScriptHex = bytesToHex(covenantOutput(reserve, rulesHash()).script);
  const reserveVout = opts.seatCount;
  tx.addOutput({ lockingScript: LockingScript.fromHex(covScriptHex), satoshis: reserve });
  tx.addOutput({ lockingScript: new P2PKH().lock(opts.funder.address), change: true });
  await tx.fee();
  await tx.sign();

  return { network: opts.network, hex: tx.toHex(), genesisTxid: tx.id('hex') as string, seats, reserve: { satoshis: reserve, vout: reserveVout } };
}

/** Build the table genesis AND broadcast it to the chosen network. */
export async function createTable(opts: TableOpts): Promise<TableResult> {
  const built = await buildTableTx(opts);
  let bc: { txid: string };
  if (opts.network === 'regtest') {
    if (!opts.node) throw new Error('regtest needs a node');
    bc = await rpcBroadcast(built.hex, opts.node.url, opts.node.user, opts.node.pass);
  } else {
    bc = await opts.funder.broadcast(built.hex, { confirmRealValue: opts.confirmRealValue ?? false });
  }
  return { ...built, broadcast: bc };
}
