// Capture a REAL game's ordered relay log + its final canonical state hash, so the
// native GameReplay can be cross-validated end-to-end: process the SAME log and
// produce the SAME state hash as the web NetTable (the live-multiplayer read path).
import { writeFileSync } from 'node:fs';
import { InMemoryRelay } from '../packages/chat/src/relay.ts';
import { gameIdentityFrom } from '../packages/channel/src/index.ts';
import { NetTable } from '../packages/table/src/index.ts';
import { hashState } from '../packages/conformance/src/index.ts';

const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const GID = 'a1'.repeat(32);

const relay = new InMemoryRelay();
const masters = [new Uint8Array(32).fill(11), new Uint8Array(32).fill(22)];
const peers = masters.map((m) => new NetTable(relay, 'p', () => {}, { identity: gameIdentityFrom(m, GID), gameId: GID }));
peers.forEach((p) => p.connect());
peers[0]!.createTable(2, 'regtest');
peers.forEach((p) => p.joinSeat());
// (no deck-entropy round here — declared deck order; the dealerless-shuffle replay
// is a follow-up that also ports the deck permutation. This validates the core
// replay: table/seat/start/beacon-roll/action.)
peers[0]!.start();

// drive a few turns; the beacon auto-resolves rolls (submit(ROLL) is a no-op).
for (let step = 0; step < 400; step++) {
  const s = peers[0]!.state;
  if (!s || s.phase === 'GAME_OVER' || s.turnIndex > 5) break;
  const actor = peers.find((p) => p.mySeat === s.current);
  if (!actor) break;
  if (s.phase === 'AWAIT_BUY') actor.submit({ type: 'DECLINE' });
  else if (s.phase === 'AWAIT_TAX') actor.submit({ type: 'PAY_TAX', choice: 'flat' });
  else if (s.phase === 'AWAIT_POST') actor.submit({ type: 'END_TURN' });
  else actor.submit({ type: 'ROLL', dice: [1, 1] }); // no-op; lets the loop pump the beacon
}

const log = relay.history().map(hx);
const stateHash = hashState(peers[0]!.state!);
const out = 'apps/native/Estates.Conformance/replay-vectors.json';
writeFileSync(out, JSON.stringify({ gameId: GID, log, stateHash, frames: log.length, turnIndex: peers[0]!.state!.turnIndex }, null, 2));
console.log(`wrote ${out}: ${log.length} frames, turnIndex ${peers[0]!.state!.turnIndex}, stateHash ${stateHash.slice(0, 16)}…`);
