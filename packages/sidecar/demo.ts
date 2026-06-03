/**
 * Runnable IP-to-IP on-chain game demo:  pnpm --filter @estates/sidecar run demo
 *
 * Spins up two peers (Alice, Bob) connected over REAL TCP loopback sockets,
 * authenticated end-to-end, and plays a full game where EVERY move is an on-chain
 * BSV transaction sent over the socket. Both peers independently reach the same
 * state and the same on-chain transcript — no relay, no referee, no third party.
 */
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { identityFrom } from '@estates/channel';
import { genMaster } from '@estates/keys';
import { listen, connect, type PeerLink } from '@estates/link';
import { type MapContext } from '@estates/chainmap';
import { commitOutput, encodeActionCommit } from '@estates/txmap';
import { buildGenesis } from '@estates/ledger';
import { type EngineConfig } from '@estates/engine';
import { GamePeer } from './src/index.ts';

const pkh = (i: number) => new Uint8Array(createHash('sha256').update(new Uint8Array([i & 0xff, 0x5a])).digest()).slice(0, 20);
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(p: () => boolean, ms = 5000): Promise<void> { const t0 = Date.now(); while (!p()) { if (Date.now() - t0 > ms) throw new Error('timeout'); await delay(5); } }

const config: EngineConfig = { network: 'regtest', seatCount: 2, bankReserve: 1_000_000 };
const ctx: MapContext = { gameId: new Uint8Array(32).fill(7), genesis: { txid: 'ef'.repeat(32), vout: 0 }, seatPkhs: [pkh(1), pkh(2)], bankPkh: pkh(9) };
const genesis = buildGenesis({ fundingOutpoint: { txid: 'ab'.repeat(32), vout: 0 }, cursorScript: commitOutput(encodeActionCommit({ type: 'END_TURN' }, 0, 0), pkh(9)).script, seatFunds: [{ satoshis: 1500, script: pkh(1) }, { satoshis: 1500, script: pkh(2) }] });

// Each player's OWN non-custodial key is the seat identity (signs moves + addresses chat).
const aliceKey = genMaster(); const bobKey = genMaster();
const aliceId = identityFrom(aliceKey.priv); const bobId = identityFrom(bobKey.priv);
let bob: GamePeer | null = null;
const server = await listen(0, bobId, (link: PeerLink) => { bob = new GamePeer(link, bobId, 1, 0, config, ctx, genesis); });
const port = (server.address() as AddressInfo).port;
console.log(`# Bob listening on 127.0.0.1:${port}; Alice dialing… (real TCP, mutually authenticated)`);

const aliceLink = await connect('127.0.0.1', port, aliceId);
const alice = new GamePeer(aliceLink, aliceId, 0, 1, config, ctx, genesis);
bob!.onChat((text, from) => console.log(`  [chat] ${from.slice(0, 8)}…: ${text}`));
alice.chat('gl hf — every move signed, every sat on chain');
await waitFor(() => bob !== null);
console.log(`# connected. genesis ${genesis.cursor.txid.slice(0, 16)}…  every move below is a real on-chain tx sent over the socket\n`);

for (let i = 0; i < 400 && alice.state.phase !== 'GAME_OVER' && alice.state.turnIndex <= 14; i++) {
  const mover = alice.myTurn() ? alice : bob!.myTurn() ? bob! : null;
  if (!mover) { await delay(10); continue; }
  const before = JSON.stringify(alice.state);
  const beforeLen = alice.transcript().length;
  const wasRoll = alice.state.phase === 'AWAIT_ROLL';
  mover.takeTurn();
  // wait for the move (incl. the commit→reveal beacon round for a ROLL) to settle
  await waitFor(() => JSON.stringify(alice.state) === JSON.stringify(bob!.state) && JSON.stringify(alice.state) !== before);
  const id = alice.transcript()[beforeLen] ?? '';
  const dice = wasRoll && alice.state.lastRoll ? ` 🎲 ${alice.state.lastRoll[0]}+${alice.state.lastRoll[1]} (beacon)` : '';
  console.log(`  seat ${mover.seat} move → tx ${id.slice(0, 16)}…${dice}  (turn ${alice.state.turnIndex})  balances ${alice.state.seats.map((s) => s.balance).join('/')}  reserve ${alice.state.bankReserve}`);
}

const same = JSON.stringify(alice.state) === JSON.stringify(bob!.state);
const sameTx = JSON.stringify(alice.transcript()) === JSON.stringify(bob!.transcript());
const total = alice.state.seats.reduce((n, s) => n + s.balance, 0) + alice.state.bankReserve;
console.log(`\n# both peers converged: state=${same ? 'IDENTICAL' : 'DIVERGED'}  transcript=${sameTx ? 'IDENTICAL' : 'DIVERGED'}  (${alice.transcript().length} txids)`);
console.log(`# sats conserved: ${total} == ${1500 + 1500 + 1_000_000 ? '1003000' : ''}  (no minting)`);
aliceLink.close(); server.close();
process.exit(same && sameTx && total === 1_003_000 ? 0 : 1);
