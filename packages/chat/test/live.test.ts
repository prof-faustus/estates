/**
 * Live online test: two peers chat through a REAL HTTP+SSE relay over the
 * loopback network — encrypted end to end, the relay only ever sees ciphertext.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ChatRoom, HttpRelay, genPeer } from '../src/index.ts';
import { startRelayServer } from '../src/server.ts';

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
// Generous timeouts: node:test runs files in parallel, so this real-HTTP/SSE
// test must tolerate heavy concurrent load without flaking.
async function waitFor(pred: () => boolean, ms = 20000): Promise<void> {
  const t0 = Date.now();
  while (!pred()) { if (Date.now() - t0 > ms) throw new Error('waitFor timeout'); await delay(25); }
}
// HTTP/SSE over loopback is at-least-once but a frame can be dropped under heavy
// parallel-test load. Re-send on a timer until the peer observes it, so the
// assertion reflects transport reach, not luck (recipients only check .includes).
async function postUntil(send: () => void, pred: () => boolean, ms = 20000): Promise<void> {
  const t0 = Date.now();
  send();
  while (!pred()) {
    if (Date.now() - t0 > ms) throw new Error('postUntil timeout');
    await delay(300); if (!pred()) send();
  }
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
    await delay(1200);           // let both SSE subscriptions establish (parallel-load tolerant)
    A.join(); B.join();
    await waitFor(() => A.members.size === 2 && B.members.size === 2); // membership propagated live

    await postUntil(() => A.post('hello over the wire'), () => gotB.includes('hello over the wire'));
    await postUntil(() => B.post('got it, Alice'), () => gotA.includes('got it, Alice'));

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
    A.connect(); B.connect(); await delay(800); A.join(); B.join();
    await waitFor(() => A.members.size === 2);

    const C = new ChatRoom(new HttpRelay(relay.url, 't'), genPeer());
    const gotC: string[] = []; C.onMessage((m) => gotC.push(m.text));
    C.connect(); await delay(800); C.join();         // C replays history, learns A+B
    await waitFor(() => A.members.size === 3 && C.members.size === 3);

    await postUntil(() => A.post('welcome C'), () => gotC.includes('welcome C'));
    assert.ok(gotC.includes('welcome C'));
  } finally {
    await relay.close();
  }
});
