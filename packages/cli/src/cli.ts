#!/usr/bin/env node
/**
 * estates — ESTATES launcher CLI. You choose the network.
 *
 *   estates keygen --network testnet
 *   estates table  --network regtest --seats 2 \
 *                  --rpc-url http://127.0.0.1:18332 --rpc-user U --rpc-pass P
 *   estates table  --network testnet --seats 2 --funder-wif <WIF> \
 *                  --funding <txid>:<vout>:<sats>:<rawhex>
 *   estates table  --network mainnet ... --confirm-real-value   (REAL value)
 */
import { randomBytes } from 'node:crypto';
import { Wallet, type Network } from '@estates/wallet';
import { createTable, nodeFund, type NodeRpc, type Funding } from './index.ts';

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
/** The 32-byte game id: parse a supplied 64-hex value, or mint a fresh random one. */
function parseGameId(hex: string | undefined): Uint8Array {
  if (hex === undefined) return new Uint8Array(randomBytes(32));
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error('--game-id must be 64 hex chars (32 bytes)');
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return b;
}

function parse(argv: string[]): { _: string[]; flags: Record<string, string | true> } {
  const _: string[] = []; const flags: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const v = argv[i + 1] && !argv[i + 1]!.startsWith('--') ? argv[++i]! : true;
      flags[k] = v;
    } else _.push(a);
  }
  return { _, flags };
}

const { _, flags } = parse(process.argv.slice(2));
const cmd = _[0];
const network = (flags.network as Network) || 'regtest';
const str = (k: string): string | undefined => (typeof flags[k] === 'string' ? (flags[k] as string) : undefined);

function nodeFromFlags(): NodeRpc | undefined {
  const url = str('rpc-url'); if (!url) return undefined;
  return { url, user: str('rpc-user') ?? '', pass: str('rpc-pass') ?? '' };
}

async function main(): Promise<void> {
  if (cmd === 'keygen') {
    const w = Wallet.random(network);
    console.log(JSON.stringify({ network, address: w.address, wif: w.key.toWif() }, null, 2));
    return;
  }

  if (cmd === 'table') {
    const seatCount = Number(str('seats') ?? '2');
    const node = nodeFromFlags();
    const reserveSalaryCap = str('reserve-cap') ? Number(str('reserve-cap')) : undefined;

    // the 32-byte table/game id binds the bank reserve covenant to THIS game (one-game
    // lifecycle). Supply it (shared via the lobby) with --game-id <64hex>, or mint a
    // fresh one for a brand-new table; it is echoed in the output so peers can match.
    const gameId = parseGameId(str('game-id'));

    // funder + funding UTXO
    const funder = str('funder-wif') ? Wallet.fromWif(str('funder-wif')!, network) : Wallet.random(network);
    let funding: Funding;
    if (str('funding')) {
      const [txid, vout, sats, raw] = str('funding')!.split(':');
      funding = { txid: txid!, vout: Number(vout), satoshis: Number(sats), raw: raw! };
    } else if (network === 'regtest' && node) {
      console.error(`# regtest: auto-funding funder ${funder.address} from the node…`);
      funding = await nodeFund(node, funder.address, 2.0);
    } else {
      throw new Error('provide --funding <txid>:<vout>:<sats>:<rawhex> (testnet/mainnet need a real UTXO)');
    }

    const res = await createTable({
      network, funder, funding, seatCount, gameId,
      ...(reserveSalaryCap !== undefined ? { reserveSalaryCap } : {}),
      ...(node ? { node } : {}),
      confirmRealValue: flags['confirm-real-value'] === true,
    });
    console.log(JSON.stringify({ ...res, gameId: toHex(gameId) }, null, 2));
    return;
  }

  console.error('usage: estates <keygen|table> --network <regtest|testnet|mainnet> [...]');
  process.exit(2);
}

main().catch((e) => { console.error('error:', e instanceof Error ? e.message : String(e)); process.exit(1); });
