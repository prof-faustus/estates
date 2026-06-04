import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { genIdentity } from '@estates/channel';
import { listen, connect, type PeerLink } from '../src/index.ts';

const te = (s: string) => new TextEncoder().encode(s);
const td = (b: Uint8Array) => new TextDecoder().decode(b);
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

test('two peers connect over REAL TCP, authenticate, and exchange encrypted frames', async () => {
  const alice = genIdentity(); const bob = genIdentity();
  const bobGot: string[] = []; const aliceGot: string[] = [];
  let serverLink: PeerLink | null = null;

  const server = await listen(0, bob, (link) => {
    serverLink = link;
    link.onMessage((m) => bobGot.push(td(m)));
    link.send(te('hello alice, this is bob'));
  });
  const port = (server.address() as AddressInfo).port;
  try {
    const clientLink = await connect('127.0.0.1', port, alice);
    clientLink.onMessage((m) => aliceGot.push(td(m)));
    await delay(50); // let the server-side onPeer + initial send land
    clientLink.send(te('hi bob, this is alice'));

    const t0 = Date.now();
    while ((bobGot.length === 0 || aliceGot.length === 0) && Date.now() - t0 < 3000) await delay(10);

    assert.deepEqual(aliceGot, ['hello alice, this is bob'], 'Alice received Bob’s frame, decrypted');
    assert.deepEqual(bobGot, ['hi bob, this is alice'], 'Bob received Alice’s frame, decrypted');
    // mutual identity learned over the wire
    assert.equal(Buffer.from(clientLink.peerIdPub).toString('hex'), Buffer.from(bob.pub).toString('hex'));
    assert.ok(serverLink);
    assert.equal(Buffer.from(serverLink!.peerIdPub).toString('hex'), Buffer.from(alice.pub).toString('hex'));

    clientLink.close();
  } finally {
    server.close();
  }
});

test('many frames stream in order across the TCP link', async () => {
  const a = genIdentity(); const b = genIdentity();
  const got: string[] = [];
  const server = await listen(0, b, (link) => link.onMessage((m) => got.push(td(m))));
  const port = (server.address() as AddressInfo).port;
  try {
    const link = await connect('127.0.0.1', port, a);
    for (let i = 0; i < 50; i++) link.send(te(`move-${i}`));
    const t0 = Date.now();
    while (got.length < 50 && Date.now() - t0 < 3000) await delay(10);
    assert.equal(got.length, 50, 'all frames delivered');
    assert.deepEqual(got, Array.from({ length: 50 }, (_, i) => `move-${i}`), 'in order, none lost');
    link.close();
  } finally {
    server.close();
  }
});

test('a dialer that cannot authenticate is dropped', async () => {
  // server speaks our protocol; a client sending garbage instead of a Hello is closed.
  const b = genIdentity();
  const server = await listen(0, b, () => { /* should never fire */ });
  const port = (server.address() as AddressInfo).port;
  try {
    const net = await import('node:net');
    const sock = net.connect(port, '127.0.0.1');
    await new Promise((r) => sock.on('connect', r));
    const body = Buffer.from(JSON.stringify({ t: 'hello', hello: { idPub: 'zz', ephPub: 'zz', nonce: 'zz', sig: 'zz' } }));
    const len = Buffer.allocUnsafe(4); len.writeUInt32BE(body.length, 0);
    sock.write(Buffer.concat([len, body]));
    const closed = await new Promise<boolean>((r) => { sock.on('close', () => r(true)); setTimeout(() => r(false), 1500); });
    assert.ok(closed, 'server dropped the unauthenticated dialer');
  } finally {
    server.close();
  }
});

test('oversized frame announcement (#12) is dropped before the buffer grows', async () => {
  const b = genIdentity();
  const server = await listen(0, b, () => { /* never authenticates */ });
  const port = (server.address() as AddressInfo).port;
  try {
    const net = await import('node:net');
    const sock = net.connect(port, '127.0.0.1');
    await new Promise((r) => sock.on('connect', r));
    // announce a 4 GiB frame but send nothing — the server must drop us, not buffer.
    const len = Buffer.allocUnsafe(4); len.writeUInt32BE(0xffffffff, 0);
    sock.write(len);
    const closed = await new Promise<boolean>((r) => { sock.on('close', () => r(true)); setTimeout(() => r(false), 1500); });
    assert.ok(closed, 'server dropped the peer announcing an oversized frame');
  } finally {
    server.close();
  }
});

test('malformed handshake JSON (#13) destroys only that socket, no throw/crash', async () => {
  const b = genIdentity();
  let crashed = false;
  const prior = process.listeners('uncaughtException');
  const onErr = (): void => { crashed = true; };
  process.once('uncaughtException', onErr);
  const server = await listen(0, b, () => { /* never */ });
  const port = (server.address() as AddressInfo).port;
  try {
    const net = await import('node:net');
    const sock = net.connect(port, '127.0.0.1');
    await new Promise((r) => sock.on('connect', r));
    const body = Buffer.from('{ this is : not json ]');
    const len = Buffer.allocUnsafe(4); len.writeUInt32BE(body.length, 0);
    sock.write(Buffer.concat([len, body]));
    const closed = await new Promise<boolean>((r) => { sock.on('close', () => r(true)); setTimeout(() => r(false), 1500); });
    assert.ok(closed, 'offending socket destroyed');
    assert.equal(crashed, false, 'no uncaught exception escaped the handler');
  } finally {
    process.removeListener('uncaughtException', onErr);
    if (prior.length === 0) { /* nothing to restore */ }
    server.close();
  }
});
