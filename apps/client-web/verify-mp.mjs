// Headless proof: two real peers over the LIVE relay play a human-started game
// and stay in lockstep. No bots; the host starts; turns alternate.
import { NetTable, makeRelay } from './src/game.ts';

const RELAY = 'http://127.0.0.1:8788';
const CH = 'verify-' + Math.random().toString(36).slice(2, 7);
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(p, ms = 8000) { const t0 = Date.now(); while (!p()) { if (Date.now() - t0 > ms) throw new Error('timeout'); await delay(30); } }

const A = new NetTable(makeRelay(RELAY, CH), 'Alice', () => {});
const B = new NetTable(makeRelay(RELAY, CH), 'Bob', () => {});
A.connect(); B.connect();
await delay(400);

A.createTable(2, 'regtest');         // host (human) opens a 2-seat waiting room
await waitFor(() => B.view().phase === 'lobby');
A.joinSeat();                        // real people take seats
B.joinSeat();
await waitFor(() => A.view().seats.length === 2 && B.view().seats.length === 2);
console.log('lobby: both seated; started yet?', A.view().phase);  // must be 'lobby' (NOT started)
if (A.view().phase !== 'lobby') throw new Error('game started before host clicked start!');

A.start();                           // HUMAN host starts — nothing else does
await waitFor(() => A.view().phase === 'playing' && B.view().phase === 'playing');
console.log('host started the game; both playing.');

// drive each seat's own turns (these are the humans acting via their client)
function actFor(peer) {
  const v = peer.view();
  if (!v.myTurn || !v.state) return;
  const s = v.state;
  if (s.phase === 'AWAIT_ROLL') peer.submit({ type: 'ROLL', dice: [ (Math.floor(Math.random()*6)+1), (Math.floor(Math.random()*6)+1) ] });
  else if (s.phase === 'AWAIT_BUY') peer.submit({ type: 'DECLINE' });
  else if (s.phase === 'AWAIT_TAX') peer.submit({ type: 'PAY_TAX', choice: 'flat' });
  else if (s.phase === 'AWAIT_POST') peer.submit({ type: 'END_TURN' });
}

for (let i = 0; i < 200; i++) {
  actFor(A); actFor(B);
  await delay(60);
  const sa = A.view().state, sb = B.view().state;
  if (sa && sb && (sa.turnIndex >= 6 || sa.phase === 'GAME_OVER')) break;
}
await delay(400);

const sa = A.view().state, sb = B.view().state;
const eq = sa && sb && sa.turnIndex === sb.turnIndex && sa.current === sb.current
  && JSON.stringify(sa.seats.map(x=>x.balance)) === JSON.stringify(sb.seats.map(x=>x.balance));
console.log('A turnIndex', sa?.turnIndex, 'current', sa?.current, 'balances', sa?.seats.map(x=>x.balance));
console.log('B turnIndex', sb?.turnIndex, 'current', sb?.current, 'balances', sb?.seats.map(x=>x.balance));
console.log(eq ? 'PASS: real 2-player game stayed in lockstep over the live relay' : 'FAIL: peers diverged');
process.exit(eq ? 0 : 1);
