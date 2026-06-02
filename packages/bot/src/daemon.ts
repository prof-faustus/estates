#!/usr/bin/env node
/**
 * estates-bot — a SIMULATED PLAYER that runs as its own process.
 *
 * This is NOT a bot living inside another player's app (that would be a cheat).
 * It is a standalone remote participant: it holds its OWN wallet/keys/funds, it
 * connects to a table OVER THE RELAY SOCKET exactly like a remote human, it
 * claims its OWN seat, and it auto-plays ONLY that seat. It NEVER starts a game
 * (only the human host does) and it never touches anyone else's seat or money.
 *
 * Run one (or several) of these alongside the desktop app to really test online
 * play — each is a distinct player on the wire. It can also chat over the socket.
 *
 *   node --experimental-strip-types packages/bot/src/daemon.ts \
 *        --table <table-address> [--relay http://127.0.0.1:8788] \
 *        [--name sim] [--network regtest] [--wif <own-WIF>] [--say "gl hf"]
 *
 * The bot funds/defunds with its OWN wallet only — it is given no one else's key.
 */
import { Wallet, type Network } from '@estates/wallet';
import { NetTable, LobbyClient, makeRelay, DEFAULT_RELAY, LOBBY_CHANNEL, type NetworkMode } from '@estates/table';
import { ChatRoom, HttpRelay, genPeer } from '@estates/chat';

function parse(argv: string[]): Record<string, string | true> {
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const k = a.slice(2);
      flags[k] = argv[i + 1] && !argv[i + 1]!.startsWith('--') ? argv[++i]! : true;
    }
  }
  return flags;
}
const str = (f: Record<string, string | true>, k: string): string | undefined =>
  typeof f[k] === 'string' ? (f[k] as string) : undefined;

function main(): void {
  const flags = parse(process.argv.slice(2));
  const relayUrl = str(flags, 'relay') ?? DEFAULT_RELAY;
  const name = str(flags, 'name') ?? 'sim';
  const network = (str(flags, 'network') ?? 'regtest') as NetworkMode;

  // The bot's OWN wallet (its own funds). Generated unless you hand it one.
  const wallet = str(flags, 'wif')
    ? Wallet.fromWif(str(flags, 'wif')!, network as Network)
    : Wallet.random(network as Network);

  console.log(`# estates-bot "${name}" — simulated remote player`);
  console.log(`#   relay:   ${relayUrl}`);
  console.log(`#   network: ${network}`);
  console.log(`#   wallet:  ${wallet.address}   (its OWN funds — fund this address to give the bot money)`);

  const tableAddr = str(flags, 'table');
  if (tableAddr) {
    joinTable(tableAddr, relayUrl, name, flags);     // a specific table address was given
  } else {
    // No URL to type: discover open tables on the lobby and join the newest one.
    console.log('# no --table given; watching the lobby for an open table to join…');
    const lobby = new LobbyClient(makeRelay(LOBBY_CHANNEL, relayUrl), () => {});
    lobby.connect();
    let joined = false;
    const tick = setInterval(() => {
      if (joined) return;
      const open = lobby.list().filter((t) => t.network === network);
      if (open.length > 0) {
        joined = true; clearInterval(tick);
        const t = open[0]!;
        console.log(`# found open table "${t.name}" (${t.maxSeats}p · ${t.network}) at ${t.addr.slice(0, 8)}… — joining over the socket.`);
        joinTable(t.addr, relayUrl, name, flags);
      }
    }, 500);
  }
}

/** Connect to a table OVER THE RELAY as a separate remote simulated player. */
function joinTable(tableAddr: string, relayUrl: string, name: string, flags: Record<string, string | true>): void {
  console.log(`#   table:   ${tableAddr}`);
  let lastTurn = -1;
  const render = (): void => {
    const v = table.view();
    if (v.phase === 'lobby') {
      console.log(`[lobby] seat ${v.mySeat ?? '—'} · ${v.seats.length}/${v.maxSeats} seats · waiting for the HUMAN host to start`);
    } else if (v.phase === 'playing' && v.state) {
      const s = v.state;
      if (s.turnIndex !== lastTurn) {            // one line per turn — a simple live "GUI"
        lastTurn = s.turnIndex;
        const me = v.mySeat;
        const bal = me !== null ? s.seats[me]?.balance : undefined;
        console.log(`[turn ${s.turnIndex}] current=seat ${s.current} phase=${s.phase}` +
          (me !== null ? ` · me=seat ${me} (${bal} sat${v.myTurn ? ', MY TURN — auto-playing' : ''})` : '') +
          (s.phase === 'GAME_OVER' ? ` · 🏆 winner=seat ${s.winner}` : ''));
      }
      if (s.phase === 'GAME_OVER') { console.log('# game over — the simulated player is done.'); process.exit(0); }
    }
  };

  // Connect to the table OVER THE RELAY in auto-play mode, then claim our own seat.
  const table = new NetTable(makeRelay(tableAddr, relayUrl), name, render, { autoPlay: true });
  table.connect();

  // Optional: chat over the socket like a real remote player would.
  const chat = new ChatRoom(new HttpRelay(relayUrl, tableAddr), genPeer(), name);
  chat.onMessage((m) => { if (m.from !== chat.me.address) console.log(`[chat] ${chat.members.get(m.from)?.name ?? m.from.slice(0, 8)}: ${m.text}`); });
  chat.connect();

  // Give subscriptions a moment to establish, then join + greet (test-only timing).
  setTimeout(() => {
    chat.join();
    table.joinSeat(true);                         // claim our OWN seat, flagged as a simulated player
    const say = str(flags, 'say');
    if (say) setTimeout(() => chat.post(say), 800);
    console.log(`# joined as a simulated player; will auto-play only my own seat once the human host starts. Ctrl+C to leave.`);
  }, 1000);

  // Leave cleanly (money + assets default to the leader) on Ctrl+C.
  const bye = (): void => { try { table.leaveGame(); } catch { /* not seated yet */ } setTimeout(() => process.exit(0), 300); };
  process.on('SIGINT', bye);
  process.on('SIGTERM', bye);
}

main();
