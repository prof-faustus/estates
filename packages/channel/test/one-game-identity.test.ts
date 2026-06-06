// One-game keys derived from the player's OWN non-custodial master: the same
// wallet yields a DISTINCT gameplay signing key per game, so a seat key never
// serves two games — while the player still fully controls it (no throwaway).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@estates/keys';
import { gameIdentityFrom, identityFrom, signingKeyFromMaster } from '../src/index.ts';

const master = new Uint8Array(32).fill(7);
const GID_A = 'a1'.repeat(32);
const GID_B = 'b2'.repeat(32);

test('the SAME master yields a DIFFERENT signing key in different games', () => {
  const a = gameIdentityFrom(master, GID_A);
  const b = gameIdentityFrom(master, GID_B);
  assert.notEqual(bytesToHex(a.signPub), bytesToHex(b.signPub), 'per-game seat keys are distinct (one-game keys)');
  // the secp256k1 master pub (ECDH / wallet) is the SAME — it IS the player's key
  assert.equal(bytesToHex(a.pub), bytesToHex(b.pub), 'same non-custodial master controls both');
});

test('the per-game key is DETERMINISTIC: same master + same game reproduces it', () => {
  const a1 = gameIdentityFrom(master, GID_A);
  const a2 = gameIdentityFrom(master, GID_A);
  assert.equal(bytesToHex(a1.signPub), bytesToHex(a2.signPub), 'a player can reproduce their own one-game key');
});

test('a per-game key differs from the legacy game-independent key', () => {
  const game = gameIdentityFrom(master, GID_A);
  const legacy = identityFrom(master);
  assert.notEqual(bytesToHex(game.signPub), bytesToHex(legacy.signPub), 'gameId domain-separates the derivation');
  // signingKeyFromMaster with/without gameId matches the two derivations
  assert.equal(bytesToHex(signingKeyFromMaster(master, GID_A).pub), bytesToHex(game.signPub));
  assert.equal(bytesToHex(signingKeyFromMaster(master).pub), bytesToHex(legacy.signPub));
});

test('different players in the same game get different seat keys', () => {
  const p1 = gameIdentityFrom(new Uint8Array(32).fill(1), GID_A);
  const p2 = gameIdentityFrom(new Uint8Array(32).fill(2), GID_A);
  assert.notEqual(bytesToHex(p1.signPub), bytesToHex(p2.signPub));
});

test('gameIdentityFrom rejects a bad gameId / master', () => {
  assert.throws(() => gameIdentityFrom(master, 'short'));
  assert.throws(() => gameIdentityFrom(master, 'zz'.repeat(32)));
  assert.throws(() => gameIdentityFrom(new Uint8Array(31), GID_A));
});
