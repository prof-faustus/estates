// Raw dice are NEVER accepted in live multiplayer: a signed action:ROLL — even
// from the active seat's own key — is DROPPED by rebuild(), and a bot can never
// emit a roll. Every live roll comes only from the dealerless commit→reveal beacon.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryRelay } from '@estates/chat';
import { genIdentity, signData } from '@estates/channel';
import { NetTable, botAction, type NetworkMode } from '../src/index.ts';
import { initialState } from '@estates/engine';

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

test('botAction REFUSES to produce a roll (a bot must never choose its own dice)', () => {
  const s = initialState({ network: 'regtest', seatCount: 2, bankReserve: 1_000_000 });
  assert.equal(s.phase, 'AWAIT_ROLL');
  assert.throws(() => botAction(s), /never produce a roll|beacon/i);
});

test('a SIGNED action:ROLL from the active seat is DROPPED — state stays AWAIT_ROLL', () => {
  const relay = new InMemoryRelay();
  const aliceId = genIdentity();
  const alice = new NetTable(relay, 'alice', () => {}, { identity: aliceId });
  const bob = new NetTable(relay, 'bob', () => {}, { identity: genIdentity() });
  alice.connect(); bob.connect();

  alice.createTable(2, 'regtest' as NetworkMode);
  alice.joinSeat();
  bob.joinSeat();
  // Bob leaves the transport BEFORE the deal: his seat claim persists in the log
  // (the lobby is full so the host can start), but he never participates in the
  // beacon — so the roll stays pending and the phase stays AWAIT_ROLL, giving a
  // deterministic window to prove a raw ROLL is dropped.
  bob.disconnect();
  alice.start(); // host starts; current = seat 0 = Alice, phase AWAIT_ROLL

  assert.equal(alice.state?.phase, 'AWAIT_ROLL', 'beacon roll is pending (Bob never revealed)');
  assert.equal(alice.state?.lastRoll, null);

  // Alice (the ACTIVE seat) signs a raw ROLL action with HER OWN key and publishes
  // it straight to the relay — bypassing submit() (which already no-ops ROLL).
  const signPub = toHex(aliceId.signPub);
  const msg = { kind: 'action', action: { type: 'ROLL', dice: [6, 6] } };
  const sig = toHex(signData(enc({ ...msg, signPub }), aliceId.signPriv));
  relay.publish(enc({ ...msg, id: 'raw-roll-1', signPub, sig }));

  // rebuild() must DROP the signed ROLL: the game has NOT rolled.
  assert.equal(alice.state?.phase, 'AWAIT_ROLL', 'still awaiting the beacon roll');
  assert.equal(alice.state?.lastRoll, null, 'no raw dice were applied');
});
