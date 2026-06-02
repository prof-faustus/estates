/**
 * End-to-end smoke: prove the bot DAEMON is a real, separate remote player.
 *
 * - starts a REAL HTTP+SSE relay,
 * - spawns src/daemon.ts as its OWN OS process (a child),
 * - runs a human HOST in THIS process (a different NetTable),
 * - the host creates a 2-seat table and waits; the daemon (over the socket)
 *   claims seat 1 as a simulated player; the HUMAN host starts the game,
 * - the host plays seat 0, the daemon auto-plays seat 1 over the wire,
 * - we assert the table actually progresses and the bot only plays its own seat.
 *
 * Run:  pnpm --filter @estates/bot run smoke
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startRelayServer } from '@estates/chat/server';
import { NetTable, makeRelay, newAddress } from '@estates/table';

const daemonPath = fileURLToPath(new URL('./src/daemon.ts', import.meta.url));
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main(): Promise<void> {
  const relay = await startRelayServer(0);
  const url = relay.url;
  const tableAddr = newAddress();
  console.log(`# relay listening at ${url}; table=${tableAddr}`);

  // Spawn the daemon as a SEPARATE process — a genuine remote player on the wire.
  const child = spawn(
    process.execPath,
    ['--experimental-strip-types', daemonPath,
      '--table', tableAddr, '--relay', url, '--name', 'daemon-sim', '--network', 'regtest', '--say', 'gl hf from the daemon'],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  child.stdout.on('data', (b: Buffer) => process.stdout.write(`  ┃ ${b.toString().replace(/\n(?!$)/g, '\n  ┃ ')}`));
  child.stderr.on('data', (b: Buffer) => process.stderr.write(`  ┃! ${b.toString()}`));

  // The HUMAN host, in THIS process.
  const host = new NetTable(makeRelay(tableAddr, url), 'human-host', () => {});
  host.connect();
  await delay(600);
  host.createTable(2, 'regtest');
  host.joinSeat();                 // seat 0 = human

  // Wait for the daemon to claim its own seat over the socket.
  const t0 = Date.now();
  while (host.view().seats.length < 2) {
    if (Date.now() - t0 > 15000) throw new Error('daemon never claimed a seat over the socket');
    await delay(100);
  }
  const seats = host.view().seats;
  console.log(`# both seats filled over the wire: ${seats.map((s) => `${s.seat}:${s.name}${s.bot ? '(sim)' : ''}`).join(', ')}`);
  if (!seats.some((s) => s.bot)) throw new Error('the daemon seat was not flagged as a simulated player');

  // ONLY the human starts.
  host.start();
  if (host.view().phase !== 'playing') throw new Error('host failed to start');
  console.log('# human host started the game; driving seat 0, daemon auto-plays seat 1…');

  // Drive the host's own seat; the daemon auto-plays its seat over the socket.
  const startTurn = host.state!.turnIndex;
  const deadline = Date.now() + 30000;
  while (host.state!.phase !== 'GAME_OVER' && host.state!.turnIndex < startTurn + 8 && Date.now() < deadline) {
    const s = host.state!;
    if (s.current === 0 && host.view().myTurn) {
      if (s.phase === 'AWAIT_ROLL') host.submit({ type: 'ROLL', dice: [Math.ceil(Math.random() * 6), Math.ceil(Math.random() * 6)] as const });
      else if (s.phase === 'AWAIT_BUY') host.submit({ type: 'DECLINE' });
      else if (s.phase === 'AWAIT_TAX') host.submit({ type: 'PAY_TAX', choice: 'flat' });
      else if (s.phase === 'AWAIT_POST') host.submit({ type: 'END_TURN' });
    }
    await delay(120);  // give the daemon time to take its turn over the network
  }

  const finalTurn = host.state!.turnIndex;
  console.log(`# progressed from turn ${startTurn} to turn ${finalTurn} (phase=${host.state!.phase})`);
  if (finalTurn < startTurn + 4) throw new Error(`table did not progress with the remote daemon (turn ${startTurn} -> ${finalTurn})`);

  child.kill('SIGINT');
  await delay(400);
  await relay.close();
  console.log('\n✓ SMOKE PASS: the bot daemon joined over a real socket as a separate remote player, auto-played only its own seat, and the human-started game progressed.');
  process.exit(0);
}

main().catch((e) => { console.error('\n✗ SMOKE FAIL:', e instanceof Error ? e.message : String(e)); process.exit(1); });
