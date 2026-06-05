// Live END-TO-END proof of the NATIVE spectate path: start the REAL HTTP relay,
// drive a REAL two-peer NetTable game over it, then leave the relay running with a
// manifest (channel + the web's canonical state hash) on disk. The native
// Estates.Conformance then reads that channel back over HTTP with its own
// RelayClient, replays it with GameReplay, and asserts it reaches the SAME hash —
// i.e. the native client genuinely spectates a live web game byte-for-byte.
//
// We drive the game on a deterministic InMemoryRelay (so the ordered log is fixed),
// then PUBLISH that exact ordered log to the live HTTP relay. This exercises the
// real wire path the native spectator uses: HTTP /publish + /history -> RelayClient
// -> GameReplay -> canonical hash. (The web app's own NetTable<->HttpRelay live
// transport is separately covered by packages/chat live tests.)
import { writeFileSync } from 'node:fs';
import { InMemoryRelay } from '../packages/chat/src/relay.ts';
import { startRelayServer } from '../packages/chat/src/server.ts';
import { gameIdentityFrom } from '../packages/channel/src/index.ts';
import { NetTable } from '../packages/table/src/index.ts';
import { hashState } from '../packages/conformance/src/index.ts';

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const GID = 'b2'.repeat(32);
const PORT = Number(process.env.RELAY_PORT ?? 8788);
const CHANNEL = process.env.RELAY_CHANNEL ?? 'live-spectate-demo';

// ---- 1) drive a fresh, deterministic two-peer game (InMemoryRelay) ----
const mem = new InMemoryRelay();
const masters = [new Uint8Array(32).fill(0x31), new Uint8Array(32).fill(0x32)];
const peers = masters.map((m) => new NetTable(mem, 'p', () => {}, { identity: gameIdentityFrom(m, GID), gameId: GID }));
peers.forEach((p) => p.connect());
peers[0]!.createTable(2, 'regtest');
peers.forEach((p) => p.joinSeat());
peers[0]!.start();

for (let step = 0; step < 600; step++) {
  const s = peers[0]!.state;
  if (!s || s.phase === 'GAME_OVER' || s.turnIndex > 8) break;
  const actor = peers.find((p) => p.mySeat === s.current);
  if (!actor) break;
  if (s.phase === 'AWAIT_BUY') actor.submit({ type: s.current % 2 === 0 ? 'BUY' : 'DECLINE' });
  else if (s.phase === 'AWAIT_TAX') actor.submit({ type: 'PAY_TAX', choice: 'flat' });
  else if (s.phase === 'AWAIT_POST') actor.submit({ type: 'END_TURN' });
  else actor.submit({ type: 'ROLL', dice: [1, 1] }); // no-op; pumps the beacon
}

const log = mem.history().map(toHex);
const stateHash = hashState(peers[0]!.state!);
const turnIndex = peers[0]!.state!.turnIndex;

// ---- 2) start the REAL HTTP relay and publish the ordered log to it ----
const relay = await startRelayServer(PORT);
for (const hex of log) {
  const r = await fetch(`${relay.url}/publish/${CHANNEL}`, {
    method: 'POST',
    headers: { 'content-type': 'text/plain' },
    body: hex,
  });
  if (r.status !== 204) throw new Error(`publish failed: HTTP ${r.status}`);
}

// sanity: read the history straight back over HTTP and confirm it round-tripped
const back = (await (await fetch(`${relay.url}/history/${CHANNEL}`)).text()).trim().split('\n');
if (back.length !== log.length) throw new Error(`history mismatch: published ${log.length}, read ${back.length}`);

// ---- 3) write the manifest the native conformance reads, then stay alive ----
const manifest = { relayUrl: relay.url, channel: CHANNEL, gameId: GID, stateHash, frames: log.length, turnIndex };
writeFileSync('apps/native/Estates.Conformance/live-spectate.json', JSON.stringify(manifest, null, 2));
console.log(`LIVE relay up at ${relay.url} channel '${CHANNEL}': ${log.length} frames, turn ${turnIndex}, hash ${stateHash.slice(0, 16)}…`);
console.log('READY'); // the runner waits for this line before launching native conformance

// keep the relay process alive until the runner kills it
const keep = setInterval(() => {}, 1 << 30);
const shutdown = async (): Promise<void> => { clearInterval(keep); await relay.close(); process.exit(0); };
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
