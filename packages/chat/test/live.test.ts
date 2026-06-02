/**
 * Live online test: two peers chat through a REAL HTTP+SSE relay over the
 * loopback network — encrypted end to end, the relay only ever sees ciphertext.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ChatRoom, HttpRelay, genPeer } from '../src/index.ts';
import { startRelayServer } from '../src/server.ts';

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred: () => boolean, ms = 8000): Promise<void> {
  const t0 = Date.now();
  while (!pred()) { if (Date.now() - t0 > ms) throw new Error('waitFor timeout'); await delay(20); }
}

test('two peers chat live over an HTTP+SSE relay (end-to-end encrypted)', async () => {
  const relay = await startRelayServer(0);
  try {
    const A = new ChatRoom(new HttpRelay(relay.url, 'table-7'), genPeer(), 'Alice');
    const B = new ChatRoom(new HttpRelay(relay.url, 'table-7'), genPeer(), 'Bob');
    const gotB: string[] = []; const gotA: string[] = [];
    A.onMessage((m) => gotA.push(m.text));
    B.onMessage((m) => gotB.push(m.text));

    A.connect(); B.connect();
    await delay(400);            // let both SSE subscriptions establish
    A.join(); B.join();
    await waitFor(() => A.members.size === 2 && B.members.size === 2); // membership propagated live

    A.post('hello over the wire');
    await waitFor(() => gotB.includes('hello over the wire'));
    B.post('got it, Alice');
    await waitFor(() => gotA.includes('got it, Alice'));

    // every member (incl. the sender) sees every message — real chat behaviour
    for (const got of [gotA, gotB]) {
      assert.ok(got.includes('hello over the wire'), 'received A’s message');
      assert.ok(got.includes('got it, Alice'), 'received B’s message');
    }
  } finally {
    await relay.close();
  }
});

test('a third peer reconnects live and joins the ongoing channel', async () => {
  const relay = await startRelayServer(0);
  try {
    const A = new ChatRoom(new HttpRelay(relay.url, 't'), genPeer());
    const B = new ChatRoom(new HttpRelay(relay.url, 't'), genPeer());
    A.connect(); B.connect(); await delay(120); A.join(); B.join();
    await waitFor(() => A.members.size === 2);

    const C = new ChatRoom(new HttpRelay(relay.url, 't'), genPeer());
    const gotC: string[] = []; C.onMessage((m) => gotC.push(m.text));
    C.connect(); await delay(150); C.join();         // C replays history, learns A+B
    await waitFor(() => A.members.size === 3 && C.members.size === 3);

    A.post('welcome C');
    await waitFor(() => gotC.includes('welcome C'));
    assert.ok(gotC.includes('welcome C'));
  } finally {
    await relay.close();
  }
});
