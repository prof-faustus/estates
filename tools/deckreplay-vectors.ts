// Capture a REAL game that ran the DEALERLESS DECK SHUFFLE (every seat commits→
// reveals entropy pre-start, so the deck order is jointly generated and no single
// party — not even the host — chooses it). The native GameReplay must reproduce the
// SAME participant-bound deckOrder and therefore the SAME canonical state hash. This
// is the cross-validation for Deck.cs + GameReplay's dcommit/dreveal path.
import { writeFileSync } from 'node:fs';
import { InMemoryRelay } from '../packages/chat/src/relay.ts';
import { gameIdentityFrom } from '../packages/channel/src/index.ts';
import { NetTable } from '../packages/table/src/index.ts';
import { hashState } from '../packages/conformance/src/index.ts';

const hx = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const GID = 'c3'.repeat(32);

const relay = new InMemoryRelay();
const masters = [new Uint8Array(32).fill(0x41), new Uint8Array(32).fill(0x42)];
const peers = masters.map((m) => new NetTable(relay, 'p', () => {}, { identity: gameIdentityFrom(m, GID), gameId: GID }));
peers.forEach((p) => p.connect());
peers[0]!.createTable(2, 'regtest');
peers.forEach((p) => p.joinSeat());

// DEALERLESS deck shuffle: every seat commits, then every seat reveals, BEFORE start.
peers.forEach((p) => p.commitDeckEntropy());
peers.forEach((p) => p.revealDeckEntropy());
peers[0]!.start();

for (let step = 0; step < 600; step++) {
  const s = peers[0]!.state;
  if (!s || s.phase === 'GAME_OVER' || s.turnIndex > 6) break;
  const actor = peers.find((p) => p.mySeat === s.current);
  if (!actor) break;
  if (s.phase === 'AWAIT_BUY') actor.submit({ type: 'DECLINE' });
  else if (s.phase === 'AWAIT_TAX') actor.submit({ type: 'PAY_TAX', choice: 'flat' });
  else if (s.phase === 'AWAIT_POST') actor.submit({ type: 'END_TURN' });
  else actor.submit({ type: 'ROLL', dice: [1, 1] }); // no-op; pumps the beacon
}

const finalState = peers[0]!.state!;
const log = relay.history().map(hx);
const stateHash = hashState(finalState);
// the jointly-generated order the web computed (must be present — entropy round ran)
const deckOrder = finalState.deckOrder ?? null;
if (!deckOrder) throw new Error('expected a dealerless deckOrder in the final state');

const out = 'apps/native/Estates.Conformance/deckreplay-vectors.json';
writeFileSync(out, JSON.stringify({ gameId: GID, log, stateHash, deckOrder, frames: log.length, turnIndex: finalState.turnIndex }, null, 2));
console.log(`wrote ${out}: ${log.length} frames, turn ${finalState.turnIndex}, decks [${Object.keys(deckOrder).join(', ')}], hash ${stateHash.slice(0, 16)}…`);
