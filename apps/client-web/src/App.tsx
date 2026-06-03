import { useEffect, useReducer, useRef, useState } from 'react';
import type { Action } from '@estates/engine';
import { Wallet, type Network } from '@estates/wallet';
import { Board } from './board';
import { ChatPanel } from './ChatPanel';
import { WalletPanel } from './WalletPanel';
import {
  P, SEAT_COLORS, GROUP_COLOR, NetTable, LobbyClient, makeRelay, newAddress, identityFrom,
  rollDice, ownedBy, buildable, mortgageable, unmortgageable, lastCard,
  LOBBY_CHANNEL, DEFAULT_RELAY, type NetworkMode, type TableView, type OpenTable, type Identity,
} from './game';

/** The player's table identity DERIVED from their wallet master key — the same
 *  key signs moves + addresses chat (audit #1; "use the player keys"). */
function playerIdentity(wif: string, net: Network): Identity | undefined {
  try { return identityFrom(new Uint8Array(Wallet.fromWif(wif, net).key.toArray('be', 32))); } catch { return undefined; }
}

const NETWORKS: NetworkMode[] = ['regtest', 'testnet', 'mainnet'];

export function App() {
  const [, force] = useReducer((x: number) => x + 1, 0);
  const lobbyRef = useRef<LobbyClient | null>(null);
  const tableRef = useRef<NetTable | null>(null);
  const tableAddrRef = useRef<string>('');   // the relay channel of the table we're at (to spawn bot windows)

  const [stage, setStage] = useState<'enter' | 'lobby' | 'table'>('enter');
  const [name, setName] = useState('player');
  const [ownWif, setOwnWif] = useState('');
  const [wif, setWif] = useState('');                 // YOUR wallet/identity key (persistent)

  const [seatCount, setSeatCount] = useState(2);
  const [network, setNetwork] = useState<NetworkMode>('regtest');
  const [beBanker, setBeBanker] = useState(false);
  // When ON, THIS window is a SEPARATE simulated player: it claims its own seat
  // and auto-plays ONLY that seat (a bot is never controlled from inside another
  // player's app — that is a cheat). Run a second window/instance with this ON to
  // watch a bot play as a real, remote participant. Never auto-set; you choose it.
  const [autoPlay, setAutoPlay] = useState(false);

  const identity = () => { try { return Wallet.fromWif(wif, 'testnet').address; } catch { return name; } };

  function enter() {
    const key = ownWif.trim() || Wallet.random('testnet').key.toWif();
    setWif(key);
    const lobby = new LobbyClient(makeRelay(LOBBY_CHANNEL), force, playerIdentity(key, 'testnet'));
    lobby.connect();
    lobbyRef.current = lobby;
    setStage('lobby');
  }

  function createTable() {
    const addr = newAddress();
    const myId = playerIdentity(wif, 'testnet');
    const t = new NetTable(makeRelay(addr), identity(), force, { autoPlay, ...(myId ? { identity: myId } : {}) });
    t.connect();
    t.createTable(seatCount, network);
    tableRef.current = t; tableAddrRef.current = addr;
    lobbyRef.current?.announce({ addr, name, maxSeats: seatCount, network, host: identity(), ts: Date.now() });
    setStage('table');
  }
  function joinTable(ot: OpenTable) {
    const myId = playerIdentity(wif, 'testnet');
    const t = new NetTable(makeRelay(ot.addr), identity(), force, { autoPlay, ...(myId ? { identity: myId } : {}) });
    t.connect();
    setNetwork(ot.network);
    tableRef.current = t; tableAddrRef.current = ot.addr;
    setStage('table');
  }

  // Open a NEW WINDOW that is a SEPARATE simulated player joined to THIS table.
  // It connects over the relay socket like any remote human and auto-plays only
  // its own seat. Desktop → a native Tauri window; web → a popup. You watch it.
  async function spawnBotWindow() {
    const addr = tableAddrRef.current;
    if (!addr) return;
    const net = v?.network ?? network;
    const botName = `bot-${Math.random().toString(36).slice(2, 6)}`;
    const url = `index.html?autoplay=1&table=${encodeURIComponent(addr)}&network=${net}&name=${botName}`;
    if (typeof (window as unknown as { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__ !== 'undefined') {
      const { WebviewWindow } = await import('@tauri-apps/api/webviewWindow');
      new WebviewWindow(`bot-${Date.now()}`, { url, title: `ESTATES — ${botName} (simulated player)`, width: 1100, height: 880 });
    } else {
      window.open(url, '_blank', 'width=1100,height=880');
    }
  }

  // If launched with ?autoplay=1&table=…, THIS window is a simulated player:
  // auto-enter, connect to the given table over the relay, and claim our own seat.
  useEffect(() => {
    const q = new URLSearchParams(location.search);
    if (q.get('autoplay') !== '1' || !q.get('table') || tableRef.current) return;
    const addr = q.get('table')!;
    const botName = q.get('name') || 'bot';
    const net = (q.get('network') as NetworkMode) || 'regtest';
    const key = Wallet.random('testnet').key.toWif();
    setWif(key); setName(botName); setNetwork(net); setAutoPlay(true);
    const botId = playerIdentity(key, 'testnet');
    const t = new NetTable(makeRelay(addr), botName, force, { autoPlay: true, ...(botId ? { identity: botId } : {}) });
    t.connect();
    tableRef.current = t; tableAddrRef.current = addr;
    setStage('table');
    // Claim our own seat once the table definition has propagated over the relay.
    const deadline = Date.now() + 20000;
    const iv = setInterval(() => {
      const view = t.view();
      if (view.mySeat !== null) { clearInterval(iv); return; }
      if (view.maxSeats !== null && view.freeSeats.length > 0) t.joinSeat(true);
      if (Date.now() > deadline) clearInterval(iv);
    }, 500);
    return () => clearInterval(iv);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  function returnToLobby() {
    tableRef.current?.leaveGame();   // leaving mid-game gives your money + assets to the leading player
    tableRef.current = null; setBeBanker(false); setStage('lobby'); force();
  }

  const t = tableRef.current;
  const v: TableView | null = t ? t.view() : null;
  const act = (a: Action) => t?.submit(a);
  const walletNet: Network = (v?.network ?? network) as Network;

  // ---------- ENTER ----------
  if (stage === 'enter') {
    return (
      <Shell>
        <section className="connect-card">
          <h2>Your identity &amp; wallet</h2>
          <p className="hint">No URLs. You get a Bitmessage-style address that is also your wallet.</p>
          <label>name <input value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label>your wallet WIF <input placeholder="blank = generate one (you keep the key)" value={ownWif} onChange={(e) => setOwnWif(e.target.value)} /></label>
          <label className="simtoggle">
            <input type="checkbox" checked={autoPlay} onChange={(e) => setAutoPlay(e.target.checked)} />
            this window is a simulated player (test) — auto-plays only its own seat
          </label>
          <p className="hint">A bot is a SEPARATE remote player: open another window with this ticked, join the same table, and watch it play over the network. It is never run inside another player’s app.</p>
          <button className="primary" onClick={enter}>Enter the lobby</button>
        </section>
      </Shell>
    );
  }

  // ---------- LOBBY (Bitmessage-style discovery) ----------
  if (stage === 'lobby') {
    const tables = lobbyRef.current?.list() ?? [];
    return (
      <Shell>
        <div className="lobbywrap">
          <section className="connect-card">
            <h2>Lobby</h2>
            <p className="hint">you: <code>{identity().slice(0, 16)}…</code></p>

            <h3>Open tables</h3>
            {tables.length === 0 && <p className="hint">none yet — create one below.</p>}
            <ol className="seatlist">
              {tables.map((ot) => (
                <li key={ot.addr}>
                  <b>{ot.name}</b> · {ot.maxSeats}p · {ot.network} · <code>{ot.addr.slice(0, 8)}…</code>{' '}
                  <button onClick={() => joinTable(ot)}>Join</button>
                </li>
              ))}
            </ol>

            <h3>Create a table — you decide</h3>
            <label>players
              <select value={seatCount} onChange={(e) => setSeatCount(Number(e.target.value))}>
                {[2, 3, 4, 5, 6].map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </label>
            <label>network
              <select value={network} onChange={(e) => setNetwork(e.target.value as NetworkMode)}>
                {NETWORKS.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            </label>
            <label><input type="checkbox" checked={beBanker} onChange={(e) => setBeBanker(e.target.checked)} /> be the banker &amp; fund the reserve</label>
            <button className="primary" onClick={createTable}>Open waiting room</button>
          </section>
          <WalletPanel wif={wif} network={network as Network} />
        </div>
      </Shell>
    );
  }

  // ---------- TABLE (waiting room + play) ----------
  return (
    <Shell>
      {v && v.phase === 'lobby' && (
        <div className="lobbywrap">
          <section className="connect-card">
            <h2>Waiting room — {v.seats.length}/{v.maxSeats} · {v.network}</h2>
            <ol className="seatlist">
              {Array.from({ length: v.maxSeats ?? 0 }, (_, i) => {
                const s = v.seats.find((x) => x.seat === i);
                return <li key={i}><span className="dot" style={{ background: SEAT_COLORS[i] }} /> seat {i}: {s ? <b>{s.name.slice(0, 12)}{s.bot ? ' (bot)' : ''}</b> : <i>empty</i>}</li>;
              })}
            </ol>
            <div className="lobby-actions">
              {v.mySeat === null && v.freeSeats.length > 0 && <button className="primary" onClick={() => t!.joinSeat(autoPlay)}>{autoPlay ? 'Take a seat (simulated player)' : 'Take a seat'}</button>}
              {!autoPlay && v.freeSeats.length > 0 && <button onClick={spawnBotWindow}>Add simulated player (opens a new window)</button>}
              {v.iAmHost && <button className="primary" disabled={!v.canStart} onClick={() => t!.start()}>{v.canStart ? 'Start game' : 'Start (fill all seats)'}</button>}
              {!v.iAmHost && <span className="hint">waiting for the host to start…</span>}
              <button onClick={returnToLobby}>Return to lobby</button>
            </div>
            {beBanker && (
              <div className="funding">
                <h3>You are the banker — fund the reserve ({v.network})</h3>
                <p>Send {P.scalars.salary * 200} sat to your wallet address above; it bankrolls the table’s covenant reserve. Your choice, your funds.</p>
              </div>
            )}
          </section>
          <aside className="panel">
            <WalletPanel wif={wif} network={walletNet} />
            <ChatPanel channel={`chat-${tableAddrRef.current}`} />
          </aside>
        </div>
      )}

      {v && v.phase === 'playing' && v.state && (
        <div className="main">
          <Board s={v.state} />
          <aside className="panel">
            <section className="status">
              {v.state.phase === 'GAME_OVER'
                ? <h2>🏆 Seat {v.state.winner} wins</h2>
                : <h2 style={{ color: SEAT_COLORS[v.state.current] }}>{v.myTurn ? 'Your turn' : `${v.seats.find((x) => x.seat === v.state!.current)?.name?.slice(0, 10) ?? `Seat ${v.state.current}`}’s turn`} · {v.state.phase}</h2>}
              {v.state.lastRoll && <p className="dice">🎲 {v.state.lastRoll[0]} + {v.state.lastRoll[1]} = {v.state.lastRoll[0] + v.state.lastRoll[1]}</p>}
              <p className="me">you are seat {v.mySeat} · <button className="link" onClick={returnToLobby}>end game · return to lobby</button></p>
            </section>

            {lastCard(v.state) && <section className="card"><h3>Card drawn</h3><p>{lastCard(v.state)}</p></section>}

            {v.myTurn && (
              <section className="controls">
                {v.state.phase === 'AWAIT_ROLL' && <>
                  {/* dealerless commit→reveal beacon: dice are NOT chosen by the player */}
                  <p className="hint">🎲 rolling… provably-fair dice (commit→reveal beacon, all seats)</p>
                  <button onClick={() => act({ type: 'FORFEIT' })}>Forfeit</button>
                </>}
                {v.state.phase === 'AWAIT_BUY' && <>
                  <button className="primary" onClick={() => act({ type: 'BUY' })}>Buy {P.board[v.state.pendingTitle!]!.name} ({P.board[v.state.pendingTitle!]!.base_price})</button>
                  <button onClick={() => act({ type: 'DECLINE' })}>Decline</button>
                </>}
                {v.state.phase === 'AWAIT_TAX' && <>
                  <button onClick={() => act({ type: 'PAY_TAX', choice: 'flat' })}>Pay flat 200</button>
                  <button onClick={() => act({ type: 'PAY_TAX', choice: 'percent' })}>Pay 10%</button>
                </>}
                {v.state.phase === 'AWAIT_POST' && <>
                  {buildable(v.state, v.mySeat!).map((id) => (
                    <button key={'b' + id} onClick={() => act({ type: 'BUILD', propertyId: id })}>
                      Build {P.board[id]!.name} {v.state!.titles[id]!.buildLevel >= 4 ? '🏨 hotel' : '🏠 house'} (+{P.groups[P.board[id]!.group!]!.build_cost})
                    </button>
                  ))}
                  {mortgageable(v.state, v.mySeat!).map((id) => (
                    <button key={'m' + id} onClick={() => act({ type: 'MORTGAGE', propertyId: id })}>Mortgage {P.board[id]!.name}</button>
                  ))}
                  {unmortgageable(v.state, v.mySeat!).map((id) => (
                    <button key={'u' + id} onClick={() => act({ type: 'UNMORTGAGE', propertyId: id })}>Unmortgage {P.board[id]!.name}</button>
                  ))}
                  <button className="primary" onClick={() => act({ type: 'END_TURN' })}>End turn</button>
                </>}
              </section>
            )}

            <section className="seats">
              {v.state.seats.map((pl) => (
                <div key={pl.id} className={`seat ${pl.id === v.state!.current ? 'active' : ''} ${pl.bankrupt ? 'bust' : ''}`}>
                  <div className="seat-hd">
                    <span className="dot" style={{ background: SEAT_COLORS[pl.id] }} />
                    <strong>{v.seats.find((x) => x.seat === pl.id)?.name?.slice(0, 10) ?? `Seat ${pl.id}`}{pl.id === v.mySeat ? ' (you)' : ''}</strong>
                    <span className="cash">{pl.bankrupt ? 'bankrupt' : `${pl.balance} sat`}</span>
                  </div>
                  <div className="deeds">
                    {ownedBy(v.state!, pl.id).map(({ space, title }) => (
                      <span key={space.id} className="deed" style={{ background: GROUP_COLOR[space.group ?? ''] ?? '#ccc' }}>
                        {space.name.split(' ')[0]}{title.buildLevel > 0 ? (title.buildLevel === 5 ? '🏨' : `·${title.buildLevel}`) : ''}{title.mortgaged ? '✗' : ''}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </section>

            <WalletPanel wif={wif} network={walletNet} />
            <section className="log"><h3>Transcript</h3><ol>{v.state.log.slice(-10).map((line, i) => <li key={i}>{line}</li>)}</ol></section>
            <ChatPanel channel={`chat-${tableAddrRef.current}`} />
          </aside>
        </div>
      )}
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="app">
      <header><h1>ESTATES <span className="sub">dealerless · on-chain · multiplayer</span></h1><RelayStatus /></header>
      {children}
    </div>
  );
}

// Ground-truth connection light: actually hits the relay over plain HTTP every
// 2s and shows whether THIS window can reach it. If this is red, no window can
// sync — so you see the real transport state, not a claim.
function RelayStatus() {
  const [ok, setOk] = useState<boolean | null>(null);
  const [ms, setMs] = useState<number | null>(null);
  useEffect(() => {
    let alive = true;
    const ping = async () => {
      const t0 = performance.now();
      try {
        const r = await fetch(`${DEFAULT_RELAY}/history/__ping__`, { cache: 'no-store' });
        if (alive) { setOk(r.ok); setMs(Math.round(performance.now() - t0)); }
      } catch { if (alive) { setOk(false); setMs(null); } }
    };
    void ping();
    const iv = setInterval(ping, 2000);
    return () => { alive = false; clearInterval(iv); };
  }, []);
  const label = ok === null ? 'relay: checking…' : ok ? `relay: connected${ms !== null ? ` (${ms}ms)` : ''}` : 'relay: NOT REACHABLE';
  return <span className={`relaystatus ${ok === null ? 'pending' : ok ? 'up' : 'down'}`}><span className="dot" /> {label}</span>;
}
