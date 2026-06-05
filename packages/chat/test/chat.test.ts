import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  genPeer, peerFrom, addressOf, encryptBroadcast, decryptBroadcast, isHex, isEnvelope, ChatRoom, InMemoryRelay, type ChatMessage,
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

test('browser-safety: chat join/post/receive works with NO global Buffer (isomorphic)', () => {
  // The desktop webview has no `Buffer`; a bare Buffer.from in the codec threw
  // `ReferenceError: Buffer is not defined` and crashed the chat panel on join.
  // Reproduce the browser by removing Buffer for the duration of a full round-trip.
  const g = globalThis as unknown as { Buffer?: unknown };
  const saved = g.Buffer;
  delete g.Buffer;
  try {
    const relay = new InMemoryRelay();
    const A = new ChatRoom(relay, genPeer(), 'A');
    const B = new ChatRoom(relay, genPeer(), 'B');
    const gotB: string[] = [];
    B.onMessage((m) => gotB.push(m.text));
    A.connect(); B.connect();
    assert.doesNotThrow(() => { A.join(); B.join(); }, 'join must not touch node:Buffer');
    assert.doesNotThrow(() => A.post('no-buffer-here'), 'post must not touch node:Buffer');
    assert.ok(gotB.includes('no-buffer-here'), 'message still decodes without Buffer');
  } finally {
    g.Buffer = saved;
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

// ---- WIRE DECODER: fail-closed + fuzz-proof (untrusted relay/peer bytes) -------
// Security claim: a hostile relay or peer cannot crash the receive loop, poison the
// member set, forge a chat, or DoS the client via a malformed/oversized frame.

test('isHex validates type, even-length, exact-length, and bounds (no over-alloc)', () => {
  assert.equal(isHex('ab', 1), true);
  assert.equal(isHex('abcd', 2), true);
  assert.equal(isHex('abc', 1), false, 'odd length');
  assert.equal(isHex('zz', 1), false, 'non-hex');
  assert.equal(isHex('abcd', 1), false, 'wrong exact length');
  assert.equal(isHex(123 as unknown, 1), false, 'non-string');
  assert.equal(isHex(undefined, 1), false);
  assert.equal(isHex('00'.repeat(2_000_000), undefined, 1 << 20), false, 'over the byte ceiling');
});

test('isEnvelope rejects every malformed shape (no field is dereferenced unchecked)', () => {
  const good = encryptBroadcast([genPeer().pub], new TextEncoder().encode('hi'));
  assert.equal(isEnvelope(good), true, 'a real envelope validates');
  for (const bad of [
    null, undefined, 42, 'x', [], {},
    { ephPub: 'zz', nonce: '00'.repeat(12), ct: 'aa', recipients: [] },        // bad ephPub
    { ephPub: '00'.repeat(33), nonce: '0', ct: 'aa', recipients: [{ address: '00'.repeat(20), nonce: '00'.repeat(12), ct: 'aa' }] }, // bad nonce
    { ...good, recipients: 'not-an-array' },                                    // recipients not array
    { ...good, recipients: [null] },                                           // recipient not object
    { ...good, recipients: [{ address: 'short', nonce: '00'.repeat(12), ct: 'aa' }] }, // bad recipient address
    { ...good, recipients: [] },                                               // empty recipients
  ]) {
    assert.equal(isEnvelope(bad), false, `rejected: ${(JSON.stringify(bad) ?? String(bad)).slice(0, 40)}`);
  }
});

test('decryptBroadcast is TOTAL: never throws on any malformed/hostile envelope', () => {
  const me = genPeer();
  for (const bad of [null, undefined, 42, 'x', {}, { recipients: 'x' }, { recipients: [null] }, { ephPub: 'zz' }, [], { recipients: [{}] }]) {
    let out: unknown = 'unset';
    assert.doesNotThrow(() => { out = decryptBroadcast(bad as never, me); }, `must not throw on ${JSON.stringify(bad)}`);
    assert.equal(out, null, 'malformed envelope → null');
  }
});

test('ingest is FAIL-CLOSED: hostile frames never throw, never mutate the member set', () => {
  const relay = new InMemoryRelay();
  const room = new ChatRoom(relay, genPeer());        // do NOT join → member set starts empty
  room.connect();
  const te = (s: string) => new TextEncoder().encode(s);
  const hostile: Uint8Array[] = [
    te('not json at all'),
    te('null'), te('42'), te('"a string"'), te('[]'),
    te(JSON.stringify({ kind: 'nope' })),
    te(JSON.stringify({ kind: 'join' })),                                  // missing fields
    te(JSON.stringify({ kind: 'join', address: 123, pub: 'x' })),          // wrong types
    te(JSON.stringify({ kind: 'join', address: 'aa'.repeat(20), pub: 'zz' })), // bad pub hex
    te(JSON.stringify({ kind: 'chat', from: 'aa'.repeat(20), env: {} })),  // malformed env (the old crash)
    te(JSON.stringify({ kind: 'chat', from: 'aa'.repeat(20), env: { recipients: 'x' } })),
    te(JSON.stringify({ kind: 'leave' })),
  ];
  for (const h of hostile) assert.doesNotThrow(() => relay.publish(h), 'no throw out of the receive loop');
  assert.equal(room.members.size, 0, 'no hostile frame added a member');

  // identity-spoof: a join whose address does NOT equal hash160(pub) is rejected
  const other = genPeer();
  const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  relay.publish(te(JSON.stringify({ kind: 'join', address: 'bb'.repeat(20), pub: toHex(other.pub) })));
  assert.equal(room.members.has('bb'.repeat(20)), false, 'address must bind the pubkey — spoof rejected');
  // a CORRECT join is accepted (control)
  relay.publish(te(JSON.stringify({ kind: 'join', address: other.address, pub: toHex(other.pub) })));
  assert.equal(room.members.get(other.address)?.address, other.address, 'a well-formed, address-bound join is accepted');
});

test('decoder is FUZZ-PROOF: 50k random byte/JSON frames never throw or hang', () => {
  const relay = new InMemoryRelay();
  const room = new ChatRoom(relay, genPeer());
  room.connect();
  let rng = 0xdeadbeef >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  const t0 = Date.now();
  for (let i = 0; i < 50_000; i++) {
    const len = rand() % 200;
    const b = new Uint8Array(len);
    for (let k = 0; k < len; k++) b[k] = rand() & 0xff;
    assert.doesNotThrow(() => relay.publish(b));
  }
  assert.ok(Date.now() - t0 < 8000, 'bounded work — no hang');
  assert.equal(room.members.size, 0, 'no random frame ever forged a member');
});
