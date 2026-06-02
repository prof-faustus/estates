import { useReducer, useRef, useState } from 'react';
import type { Action } from '@estates/engine';
import { Wallet, type Network } from '@estates/wallet';
import { Board } from './board';
import { ChatPanel } from './ChatPanel';
import { WalletPanel } from './WalletPanel';
import {
  P, SEAT_COLORS, GROUP_COLOR, NetTable, LobbyClient, makeRelay, newAddress,
  rollDice, ownedBy, buildable, mortgageable, unmortgageable, lastCard,
  LOBBY_CHANNEL, type NetworkMode, type TableView, type OpenTable,
} from './game';

const NETWORKS: NetworkMode[] = ['regtest', 'testnet', 'mainnet'];

export function App() {
  const [, force] = useReducer((x: number) => x + 1, 0);
  const lobbyRef = useRef<LobbyClient | null>(null);
  const tableRef = useRef<NetTable | null>(null);

  const [stage, setStage] = useState<'enter' | 'lobby' | 'table'>('enter');
  const [name, setName] = useState('player');
  const [ownWif, setOwnWif] = useState('');
  const [wif, setWif] = useState('');                 // YOUR wallet/identity key (persistent)

  const [seatCount, setSeatCount] = useState(2);
  const [network, setNetwork] = useState<NetworkMode>('regtest');
  const [beBanker, setBeBanker] = useState(false);

  const identity = () => { try { return Wallet.fromWif(wif, 'testnet').address; } catch { return name; } };

  function enter() {
    const key = ownWif.trim() || Wallet.random('testnet').key.toWif();
    setWif(key);
    const lobby = new LobbyClient(makeRelay(LOBBY_CHANNEL), force);
    lobby.connect();
    lobbyRef.current = lobby;
    setStage('lobby');
  }

  function createTable() {
    const addr = newAddress();
    const t = new NetTable(makeRelay(addr), identity(), force);
    t.connect();
    t.createTable(seatCount, network);
    tableRef.current = t;
    lobbyRef.current?.announce({ addr, name, maxSeats: seatCount, network, host: identity(), ts: Date.now() });
    setStage('table');
  }
  function joinTable(ot: OpenTable) {
    const t = new NetTable(makeRelay(ot.addr), identity(), force);
    t.connect();
    setNetwork(ot.network);
    tableRef.current = t;
    setStage('table');
  }
  function returnToLobby() { tableRef.current = null; setBeBanker(false); setStage('lobby'); force(); }

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
              {v.mySeat === null && v.freeSeats.length > 0 && <button className="primary" onClick={() => t!.joinSeat()}>Take a seat</button>}
              {v.iAmHost && v.freeSeats.length > 0 && <button onClick={() => t!.addBot()}>Add simulated player (test only)</button>}
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
          <WalletPanel wif={wif} network={walletNet} />
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
                  <button className="primary" onClick={() => act({ type: 'ROLL', dice: rollDice() })}>Roll</button>
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
            <ChatPanel />
          </aside>
        </div>
      )}
    </Shell>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="app">
      <header><h1>ESTATES <span className="sub">dealerless · on-chain · multiplayer</span></h1></header>
      {children}
    </div>
  );
}
