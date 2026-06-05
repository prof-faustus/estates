// Mandated test: live table gameplay messages must be SIGNED by a key that is
// valid for THIS GAME ONLY (bound in the game's signed key manifest). Unsigned,
// forged, stranger-key, and seat-mismatched messages must all be rejected.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { genIdentity, signData } from '@estates/channel';

const bytesToHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
import { buildManifest, hashHex, type KeyEntry, type GameKeyManifest } from '@estates/keylife';
import { acceptForGame, decodeSigned } from '../src/index.ts';

const GID = 'a1'.repeat(32);
const PARAMS = hashHex(new TextEncoder().encode('estates.v1'));
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

// Two seat players + the genesis authority, all bound to ONE game.
const authority = genIdentity();
const seat0 = genIdentity();
const seat1 = genIdentity();
const stranger = genIdentity(); // a key NOT in the manifest

const entries: KeyEntry[] = [
  { purpose: 'genesis', pub: bytesToHex(authority.signPub), keyType: 'ed25519' },
  { purpose: 'seat', pub: bytesToHex(seat0.signPub), keyType: 'ed25519', seat: 0 },
  { purpose: 'seat', pub: bytesToHex(seat1.signPub), keyType: 'ed25519', seat: 1 },
];
const manifest: GameKeyManifest = buildManifest(GID, 'estates-1', PARAMS, entries, authority.signPriv, bytesToHex(authority.signPub));

// Construct a frame exactly as the table's send() does: the signature covers
// signedBytes(msg, signPub) = JSON({...msg, signPub}); the frame adds id + sig.
function frame(msg: Record<string, unknown>, id: ReturnType<typeof genIdentity>): Uint8Array {
  const signPub = bytesToHex(id.signPub);
  const sig = bytesToHex(signData(enc({ ...msg, signPub }), id.signPriv));
  return enc({ ...msg, id: 'msg-1', signPub, sig });
}

test('a seat claim signed by the BOUND one-game seat key is accepted', () => {
  const f = frame({ kind: 'seat', seat: 0, who: bytesToHex(seat0.signPub), name: 'p0', bot: false }, seat0);
  const got = acceptForGame(f, manifest);
  assert.ok(got, 'accepted');
  assert.equal(got!.signPub, bytesToHex(seat0.signPub));
});

test('an UNSIGNED gameplay message is rejected (no signPub/sig at all)', () => {
  const unsigned = enc({ kind: 'seat', seat: 0, who: 'x', name: 'p0', bot: false }); // plain JSON, no signature
  assert.equal(decodeSigned(unsigned), null, 'decodeSigned rejects unsigned');
  assert.equal(acceptForGame(unsigned, manifest), null, 'acceptForGame rejects unsigned');
});

test('a message signed by a key NOT in the game manifest (stranger) is rejected', () => {
  const f = frame({ kind: 'action', action: { type: 'END_TURN' } }, stranger);
  assert.equal(acceptForGame(f, manifest), null, 'stranger key is not a one-game key for this game');
});

test('a seat-0 claim signed by the seat-1 key is rejected (seat must match its bound key)', () => {
  const f = frame({ kind: 'seat', seat: 0, who: bytesToHex(seat1.signPub), name: 'imposter', bot: false }, seat1);
  assert.equal(acceptForGame(f, manifest), null, 'seat number does not match the signer key binding');
});

test('a TAMPERED frame (payload changed after signing) is rejected', () => {
  const signPub = bytesToHex(seat0.signPub);
  const msg = { kind: 'action', action: { type: 'END_TURN' } };
  const sig = bytesToHex(signData(enc({ ...msg, signPub }), seat0.signPriv));
  // tamper: change the action AFTER signing
  const tampered = enc({ kind: 'action', action: { type: 'FORFEIT' }, id: 'msg-1', signPub, sig });
  assert.equal(acceptForGame(tampered, manifest), null, 'signature no longer matches the message');
});

test('an action signed by a bound seat key is accepted (authentic one-game gameplay message)', () => {
  const f = frame({ kind: 'action', action: { type: 'END_TURN' } }, seat1);
  assert.ok(acceptForGame(f, manifest), 'bound seat-1 key authenticates the action');
});

test('acceptForGame is FAIL-CLOSED on hostile payloads (never throws)', () => {
  for (const bad of [new Uint8Array(0), new Uint8Array([1, 2, 3]), enc('x'), enc(null), enc({ kind: 'evil' })]) {
    let r: unknown = 'unset';
    assert.doesNotThrow(() => { r = acceptForGame(bad, manifest); });
    assert.equal(r, null);
  }
});
