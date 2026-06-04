import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  genPeer, peerFrom, addressOf, encryptBroadcast, decryptBroadcast, ChatRoom, InMemoryRelay, type ChatMessage,
} from '../src/index.ts';

const td = (b: Uint8Array) => new TextDecoder().decode(b);
const te = (s: string) => new TextEncoder().encode(s);

test('Bitmessage-style address is deterministic and binds the pubkey', () => {
  const p = genPeer();
  assert.equal(p.address, addressOf(p.pub));
  assert.equal(p.address.length, 40); // ripemd160 = 20 bytes hex
  assert.notEqual(p.address, genPeer().address);
});

test('peerFrom: chat identity derives deterministically from the player wallet key', () => {
  const wallet = genPeer();                         // stand-in for a wallet secret key
  const a = peerFrom(wallet.priv);
  const b = peerFrom(wallet.priv);
  assert.equal(a.address, b.address, 'same key → same Bitmessage address (not a throwaway)');
  assert.equal(a.address, addressOf(wallet.pub), 'address binds the wallet pubkey');
  // a message addressed to the wallet-derived peer opens with the wallet key
  const env = encryptBroadcast([a.pub], te('hi'));
  assert.equal(td(decryptBroadcast(env, peerFrom(wallet.priv))!), 'hi');
});

test('broadcast encryption: every recipient decrypts; a non-member cannot', () => {
  const a = genPeer(), b = genPeer(), c = genPeer(), outsider = genPeer();
  const env = encryptBroadcast([a.pub, b.pub, c.pub], te('table secret'));
  assert.equal(td(decryptBroadcast(env, a)!), 'table secret');
  assert.equal(td(decryptBroadcast(env, b)!), 'table secret');
  assert.equal(td(decryptBroadcast(env, c)!), 'table secret');
  assert.equal(decryptBroadcast(env, outsider), null); // never addressed
});

test('revocation: dropping a recipient makes the next envelope unreadable to them', () => {
  const a = genPeer(), b = genPeer();
  const before = encryptBroadcast([a.pub, b.pub], te('hi'));
  assert.equal(td(decryptBroadcast(before, b)!), 'hi');
  const after = encryptBroadcast([a.pub], te('members only')); // b revoked
  assert.equal(decryptBroadcast(after, b), null);
  assert.equal(td(decryptBroadcast(after, a)!), 'members only');
});

test('tampered ciphertext fails to decrypt (AES-GCM auth)', () => {
  const a = genPeer();
  const env = encryptBroadcast([a.pub], te('intact'));
  const tampered = { ...env, ct: env.ct.replace(/.$/, (d) => (d === '0' ? '1' : '0')) };
  assert.equal(decryptBroadcast(tampered, a), null);
});

test('multiparty chat: three peers join and all receive each broadcast-encrypted message', () => {
  const relay = new InMemoryRelay();
  const A = new ChatRoom(relay, genPeer(), 'A');
  const B = new ChatRoom(relay, genPeer(), 'B');
  const C = new ChatRoom(relay, genPeer(), 'C');
  const gotA: ChatMessage[] = [], gotB: ChatMessage[] = [], gotC: ChatMessage[] = [];
  A.onMessage((m) => gotA.push(m)); B.onMessage((m) => gotB.push(m)); C.onMessage((m) => gotC.push(m));
  for (const r of [A, B, C]) r.connect();
  for (const r of [A, B, C]) r.join();

  A.post('hello table');
  B.post('hi A');

  assert.equal(A.members.size, 3, 'everyone knows the 3 members');
  for (const [who, arr] of [['A', gotA], ['B', gotB], ['C', gotC]] as const) {
    assert.deepEqual(arr.map((m) => m.text).sort(), ['hello table', 'hi A'], `${who} received both messages`);
  }
});

test('2-party ECDH (postTo): only the chosen member (+ sender) can read; others cannot', () => {
  const relay = new InMemoryRelay();
  const A = new ChatRoom(relay, genPeer(), 'A');
  const B = new ChatRoom(relay, genPeer(), 'B');
  const C = new ChatRoom(relay, genPeer(), 'C');
  const gotA: string[] = [], gotB: string[] = [], gotC: string[] = [];
  A.onMessage((m) => gotA.push(m.text)); B.onMessage((m) => gotB.push(m.text)); C.onMessage((m) => gotC.push(m.text));
  for (const r of [A, B, C]) r.connect();
  for (const r of [A, B, C]) r.join();
  A.postTo(B.me.address, 'just for B');
  assert.ok(gotB.includes('just for B'), 'recipient reads it');
  assert.ok(gotA.includes('just for B'), 'sender sees own copy');
  assert.equal(gotC.includes('just for B'), false, 'a third party cannot read a 2-party message');
});

test('the relay only sees ciphertext (never plaintext)', () => {
  const relay = new InMemoryRelay();
  const A = new ChatRoom(relay, genPeer()); const B = new ChatRoom(relay, genPeer());
  A.connect(); B.connect(); A.join(); B.join();
  A.post('SENSITIVE-PLAINTEXT');
  const wire = relay.history().map((p) => new TextDecoder().decode(p)).join('\n');
  assert.equal(wire.includes('SENSITIVE-PLAINTEXT'), false, 'plaintext must never hit the wire');
});

test('forward access control: a late joiner cannot read messages sent before it joined', () => {
  const relay = new InMemoryRelay();
  const A = new ChatRoom(relay, genPeer()); A.connect(); A.join();
  const B = new ChatRoom(relay, genPeer()); B.connect(); B.join();
  A.post('pre-C message'); // only A and B are members

  // C joins late and replays history
  const C = new ChatRoom(relay, genPeer());
  const cGot: string[] = []; C.onMessage((m) => cGot.push(m.text));
  C.connect(); C.join();
  // now everyone (incl. C) is a member; a new post reaches C
  A.post('post-C message');

  assert.equal(cGot.includes('pre-C message'), false, 'cannot read pre-join history');
  assert.equal(cGot.includes('post-C message'), true, 'reads messages sent after joining');
});

test('revoked member stops receiving a peer’s subsequent posts', () => {
  const relay = new InMemoryRelay();
  const A = new ChatRoom(relay, genPeer()); const B = new ChatRoom(relay, genPeer());
  const bGot: string[] = []; B.onMessage((m) => bGot.push(m.text));
  A.connect(); B.connect(); A.join(); B.join();
  A.post('still in'); // B reads
  A.revoke(B.me.address);
  A.post('B removed'); // A excludes B from recipients
  assert.equal(bGot.includes('still in'), true);
  assert.equal(bGot.includes('B removed'), false);
});
