import { useReducer, useRef, useState } from 'react';
import type { Action } from '@estates/engine';
import { Wallet } from '@estates/wallet';
import { Board } from './board';
import { ChatPanel } from './ChatPanel';
import {
  P, SEAT_COLORS, GROUP_COLOR, NetTable, makeRelay, rollDice, ownedBy,
  type NetworkMode, type TableView,
} from './game';

const NETWORKS: NetworkMode[] = ['regtest', 'testnet', 'mainnet'];

export function App() {
  const [, force] = useReducer((x: number) => x + 1, 0);
  const tableRef = useRef<NetTable | null>(null);

  const [name, setName] = useState('player');
  const [relayUrl, setRelayUrl] = useState('');
  const [channel, setChannel] = useState('estates-1');
  const [connected, setConnected] = useState(false);

  const [seatCount, setSeatCount] = useState(2);
  const [network, setNetwork] = useState<NetworkMode>('regtest');
  const [ownWif, setOwnWif] = useState('');
  const [funding, setFunding] = useState<{ address: string; wif: string; network: NetworkMode; own: boolean } | null>(null);

  function connect() {
    const t = new NetTable(makeRelay(relayUrl, channel), name, force);
    t.connect();
    tableRef.current = t;
    setConnected(true);
  }
  // Your choice, any time: end the game, WALK FROM whatever sats are on the
  // table, and return to the lobby/menu (NOT quit the app) to start or join again.
  function returnToLobby() {
    tableRef.current = null;
    setFunding(null);
    setConnected(false);   // back to the lobby (connect/create menu); state kept so you just re-enter
    force();
  }
  const t = tableRef.current;
  const v: TableView | null = t ? t.view() : null;

  function createTable() {
    if (!t) return;
    t.createTable(seatCount, network);
    // YOUR choice: control a wallet you have (paste a WIF) or generate a fresh
    // per-table address. Either way YOU fund it, on the network YOU chose.
    const own = ownWif.trim().length > 0;
    const w = own ? Wallet.fromWif(ownWif.trim(), network) : Wallet.random(network);
    setFunding({ address: w.address, wif: w.key.toWif(), network, own });
  }
  const act = (a: Action) => t?.submit(a);

  return (
    <div className="app">
      <header><h1>ESTATES <span className="sub">dealerless · on-chain · multiplayer</span></h1></header>

      {!connected && (
        <section className="connect-card">
          <h2>Join the relay</h2>
          <label>your name <input value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label>relay URL <input placeholder="blank = local practice" value={relayUrl} onChange={(e) => setRelayUrl(e.target.value)} /></label>
          <label>table id <input value={channel} onChange={(e) => setChannel(e.target.value)} /></label>
          <button className="primary" onClick={connect}>Enter</button>
        </section>
      )}

      {connected && v && v.phase === 'disconnected' && (
        <section className="connect-card">
          <h2>Create the table — you decide</h2>
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
          <label>your wallet WIF <input placeholder="blank = generate a fresh address" value={ownWif} onChange={(e) => setOwnWif(e.target.value)} /></label>
          <button className="primary" onClick={createTable}>Open waiting room</button>
          <p className="hint">…or wait for a host to open one on table id “{channel}”.</p>
        </section>
      )}

      {connected && v && v.phase === 'lobby' && (
        <section className="connect-card">
          <h2>Waiting room — {v.seats.length}/{v.maxSeats} seated · {v.network}</h2>
          <ol className="seatlist">
            {Array.from({ length: v.maxSeats ?? 0 }, (_, i) => {
              const s = v.seats.find((x) => x.seat === i);
              return (
                <li key={i}>
                  <span className="dot" style={{ background: SEAT_COLORS[i] }} /> seat {i}:{' '}
                  {s ? <b>{s.name}{s.bot ? ' (bot)' : ''}</b> : <i>empty</i>}
                </li>
              );
            })}
          </ol>
          <div className="lobby-actions">
            {v.mySeat === null && v.freeSeats.length > 0 && <button className="primary" onClick={() => t!.joinSeat()}>Take a seat</button>}
            {v.iAmHost && v.freeSeats.length > 0 && <button onClick={() => t!.addBot()}>Add simulated player (test only)</button>}
            {v.iAmHost && <button className="primary" disabled={!v.canStart} onClick={() => t!.start()}>{v.canStart ? 'Start game' : 'Start (fill all seats)'}</button>}
            {!v.iAmHost && <span className="hint">waiting for the host to start…</span>}
            <button onClick={returnToLobby}>Return to lobby</button>
          </div>
          {funding && (
            <div className="funding">
              <h3>Your wallet ({funding.network})</h3>
              <p>You hold the key — fund or <b>defund this wallet yourself, any time</b>. Nobody asks you for money.</p>
              <div>address: <code>{funding.address}</code></div>
              <div>WIF (your key): <code>{funding.wif}</code></div>
            </div>
          )}
        </section>
      )}

      {connected && v && v.phase === 'playing' && v.state && (
        <div className="main">
          <Board s={v.state} />
          <aside className="panel">
            <section className="status">
              {v.state.phase === 'GAME_OVER'
                ? <h2>🏆 Seat {v.state.winner} wins</h2>
                : <h2 style={{ color: SEAT_COLORS[v.state.current] }}>
                    {v.myTurn ? 'Your turn' : `${v.seats.find((x) => x.seat === v.state!.current)?.name ?? `Seat ${v.state.current}`}’s turn`} · {v.state.phase}
                  </h2>}
              {v.state.lastRoll && <p className="dice">🎲 {v.state.lastRoll[0]} + {v.state.lastRoll[1]} = {v.state.lastRoll[0] + v.state.lastRoll[1]}</p>}
              <p className="me">you are seat {v.mySeat} · <button className="link" onClick={returnToLobby}>end game · return to lobby</button></p>
            </section>

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
                {v.state.phase === 'AWAIT_POST' && <button className="primary" onClick={() => act({ type: 'END_TURN' })}>End turn</button>}
              </section>
            )}

            <section className="seats">
              {v.state.seats.map((pl) => (
                <div key={pl.id} className={`seat ${pl.id === v.state!.current ? 'active' : ''} ${pl.bankrupt ? 'bust' : ''}`}>
                  <div className="seat-hd">
                    <span className="dot" style={{ background: SEAT_COLORS[pl.id] }} />
                    <strong>{v.seats.find((x) => x.seat === pl.id)?.name ?? `Seat ${pl.id}`}{pl.id === v.mySeat ? ' (you)' : ''}</strong>
                    <span className="cash">{pl.bankrupt ? 'bankrupt' : `${pl.balance} sat`}</span>
                  </div>
                  <div className="deeds">
                    {ownedBy(v.state!, pl.id).map(({ space, title }) => (
                      <span key={space.id} className="deed" style={{ background: GROUP_COLOR[space.group ?? ''] ?? '#ccc' }}>
                        {space.name.split(' ')[0]}{title.buildLevel > 0 ? `·${title.buildLevel}` : ''}{title.mortgaged ? '✗' : ''}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </section>

            <section className="log">
              <h3>Transcript</h3>
              <ol>{v.state.log.slice(-12).map((line, i) => <li key={i}>{line}</li>)}</ol>
            </section>

            <ChatPanel />
          </aside>
        </div>
      )}
    </div>
  );
}
