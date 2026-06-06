import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@estates/keys';
import { genIdentity } from '@estates/channel';
import {
  buildManifest, verifyManifest, verifyNoCrossGameReuse, assertFreshForGame,
  hashHex, type KeyEntry, type GameKeyManifest,
} from '../src/index.ts';

const GID_A = 'a1'.repeat(32);
const GID_B = 'b2'.repeat(32);
const PARAMS = hashHex(new TextEncoder().encode('estates.v1'));

// Build a realistic per-game manifest: a genesis authority + seat keys + card keys
// + a chat key, ALL secp256k1 (NO Ed25519). Every key is bound to ONE gameId.
function makeManifest(gameId: string, seed: number): { manifest: GameKeyManifest; authority: ReturnType<typeof genIdentity>; seatPubs: string[]; cardPubs: string[] } {
  const authority = genIdentity();
  const seat0 = genIdentity(), seat1 = genIdentity();
  const card0 = genIdentity(), card1 = genIdentity();
  const chat = genIdentity();
  void seed;
  const entries: KeyEntry[] = [
    { purpose: 'genesis', pub: bytesToHex(authority.signPub), keyType: 'secp256k1' },
    { purpose: 'seat', pub: bytesToHex(seat0.signPub), keyType: 'secp256k1', seat: 0 },
    { purpose: 'seat', pub: bytesToHex(seat1.signPub), keyType: 'secp256k1', seat: 1 },
    { purpose: 'card', pub: bytesToHex(card0.pub), keyType: 'secp256k1' },
    { purpose: 'card', pub: bytesToHex(card1.pub), keyType: 'secp256k1' },
    { purpose: 'chat', pub: bytesToHex(chat.pub), keyType: 'secp256k1' },
  ];
  const manifest = buildManifest(gameId, 'estates-1', PARAMS, entries, authority.signPriv, bytesToHex(authority.signPub));
  return { manifest, authority, seatPubs: [bytesToHex(seat0.signPub), bytesToHex(seat1.signPub)], cardPubs: [bytesToHex(card0.pub), bytesToHex(card1.pub)] };
}

test('a well-formed one-game key manifest verifies', () => {
  const { manifest } = makeManifest(GID_A, 1);
  const r = verifyManifest(manifest);
  assert.ok(r.ok, r.reason);
});

test('a TAMPERED manifest (added/changed key) is rejected — the authority sig binds every entry', () => {
  const { manifest } = makeManifest(GID_A, 1);
  // swap in an attacker key for a seat without re-signing
  const evil = genIdentity();
  const tampered = { ...manifest, entries: manifest.entries.map((e, i) => i === 1 ? { ...e, pub: bytesToHex(evil.signPub) } : e) };
  assert.equal(verifyManifest(tampered).ok, false);
  // change the gameId the keys are bound to
  assert.equal(verifyManifest({ ...manifest, gameId: GID_B }).ok, false);
  // change the ruleset binding
  assert.equal(verifyManifest({ ...manifest, paramsHash: 'cc'.repeat(32) }).ok, false);
});

test('a key reused for two purposes/seats INSIDE one game is rejected', () => {
  const authority = genIdentity(); const seat0 = genIdentity();
  const dupEntries: KeyEntry[] = [
    { purpose: 'genesis', pub: bytesToHex(authority.signPub), keyType: 'secp256k1' },
    { purpose: 'seat', pub: bytesToHex(seat0.signPub), keyType: 'secp256k1', seat: 0 },
    { purpose: 'seat', pub: bytesToHex(seat0.signPub), keyType: 'secp256k1', seat: 1 }, // SAME key, two seats
  ];
  const m = buildManifest(GID_A, 'estates-1', PARAMS, dupEntries, authority.signPriv, bytesToHex(authority.signPub));
  assert.equal(verifyManifest(m).ok, false);
});

test('a manifest without exactly one genesis authority is rejected', () => {
  const authority = genIdentity(); const a2 = genIdentity();
  const two: KeyEntry[] = [
    { purpose: 'genesis', pub: bytesToHex(authority.signPub), keyType: 'secp256k1' },
    { purpose: 'genesis', pub: bytesToHex(a2.signPub), keyType: 'secp256k1' },
  ];
  const m = buildManifest(GID_A, 'estates-1', PARAMS, two, authority.signPriv, bytesToHex(authority.signPub));
  assert.equal(verifyManifest(m).ok, false);
});

test('CROSS-GAME REUSE is rejected: the same key under two different game ids fails', () => {
  // game A and game B that share NO keys → ok
  const a = makeManifest(GID_A, 1);
  const b = makeManifest(GID_B, 2);
  assert.ok(verifyNoCrossGameReuse([a.manifest, b.manifest]).ok, 'fresh keys across games pass');

  // now forge game B reusing game A's seat-0 key (re-sign B so the manifest itself is valid)
  const bAuthority = genIdentity();
  const reusedSeatPub = a.seatPubs[0]!;
  const entriesB: KeyEntry[] = [
    { purpose: 'genesis', pub: bytesToHex(bAuthority.signPub), keyType: 'secp256k1' },
    { purpose: 'seat', pub: reusedSeatPub, keyType: 'secp256k1', seat: 0 }, // REUSED from game A
  ];
  const bReuse = buildManifest(GID_B, 'estates-1', PARAMS, entriesB, bAuthority.signPriv, bytesToHex(bAuthority.signPub));
  assert.ok(verifyManifest(bReuse).ok, 'the reuse manifest is internally valid (signed) — only cross-game check catches it');
  assert.equal(verifyNoCrossGameReuse([a.manifest, bReuse]).ok, false, 'cross-game reuse REJECTED');
});

test('ONE-GAME EXPIRY: a key valid in game N is rejected in game N+1', () => {
  const a = makeManifest(GID_A, 1);
  const b = makeManifest(GID_B, 2);
  const seatPubA = a.seatPubs[0]!;
  // fresh for its own game
  assert.ok(assertFreshForGame(seatPubA, GID_A, a.manifest, [b.manifest]).ok);
  // build a B that reuses A's key, then assert it is NOT fresh for B (used in prior game A)
  const bAuth = genIdentity();
  const bReuse = buildManifest(GID_B, 'estates-1', PARAMS, [
    { purpose: 'genesis', pub: bytesToHex(bAuth.signPub), keyType: 'secp256k1' },
    { purpose: 'seat', pub: seatPubA, keyType: 'secp256k1', seat: 0 },
  ], bAuth.signPriv, bytesToHex(bAuth.signPub));
  assert.equal(assertFreshForGame(seatPubA, GID_B, bReuse, [a.manifest]).ok, false, 'key from game A expired, rejected in game B');
});

test('verifyManifest is FAIL-CLOSED on hostile input (never throws)', () => {
  for (const bad of [null, undefined, 42, 'x', [], {}, { gameId: 'zz' },
    { gameId: 'a1'.repeat(32), protocolVersion: 'v', paramsHash: 'a1'.repeat(32), authorityPub: 'a1'.repeat(32), sig: 'bb'.repeat(64), entries: 'notarray' },
    { gameId: 'a1'.repeat(32), protocolVersion: 'v', paramsHash: 'a1'.repeat(32), authorityPub: 'a1'.repeat(32), sig: 'bb'.repeat(64), entries: [{ purpose: 'evil', pub: 'aa', keyType: 'x' }] },
  ]) {
    let r: unknown = 'unset';
    assert.doesNotThrow(() => { r = verifyManifest(bad); });
    assert.equal((r as { ok: boolean }).ok, false);
  }
});

test('verifyManifest is FUZZ-PROOF: 20k random manifests never throw', () => {
  const { manifest } = makeManifest(GID_A, 1);
  let rng = 0x1234 >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  for (let i = 0; i < 20_000; i++) {
    const m: Record<string, unknown> = { ...manifest };
    const k = ['gameId', 'protocolVersion', 'paramsHash', 'authorityPub', 'sig', 'entries'][rand() % 6]!;
    m[k] = (rand() % 3 === 0) ? null : (rand() % 3 === 1) ? rand() : String(rand());
    assert.doesNotThrow(() => verifyManifest(m));
  }
});
