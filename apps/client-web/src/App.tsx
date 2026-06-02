import { useMemo, useState } from 'react';
import type { GameState, Action } from '@estates/engine';
import { Board } from './board';
import { ChatPanel } from './ChatPanel';
import {
  P, SEAT_COLORS, HUMAN, newGame, rollDice, humanDispatch, ownedBy, GROUP_COLOR,
} from './game';

export function App() {
  const [seatCount, setSeatCount] = useState(3);
  const [s, setS] = useState<GameState>(() => newGame(3));

  const act = (a: Action) => setS((cur) => humanDispatch(cur, a));
  const myTurn = s.current === HUMAN && s.phase !== 'GAME_OVER';

  const buildable = useMemo(() => {
    if (!(myTurn && s.phase === 'AWAIT_POST')) return [] as number[];
    const out: number[] = [];
    for (const [g, def] of Object.entries(P.groups)) {
      if (def.build_cost <= 0) continue;
      const ids = def.member_property_ids;
      if (!ids.every((id) => s.titles[id]?.owner === HUMAN)) continue;
      if (ids.some((id) => s.titles[id]!.mortgaged)) continue;
      const min = Math.min(...ids.map((id) => s.titles[id]!.buildLevel));
      for (const id of ids) if (s.titles[id]!.buildLevel === min && min < 5) out.push(id);
    }
    return out;
  }, [s, myTurn]);

  return (
    <div className="app">
      <header>
        <h1>ESTATES <span className="sub">offline practice (non-trustless)</span></h1>
        <div className="newgame">
          seats:
          <select value={seatCount} onChange={(e) => setSeatCount(Number(e.target.value))}>
            {[2, 3, 4, 5, 6].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
          <button onClick={() => setS(newGame(seatCount))}>New game</button>
        </div>
      </header>

      <div className="main">
        <Board s={s} />

        <aside className="panel">
          <section className="status">
            {s.phase === 'GAME_OVER'
              ? <h2>🏆 Seat {s.winner} wins</h2>
              : <h2 style={{ color: SEAT_COLORS[s.current] }}>
                  {s.current === HUMAN ? 'Your turn' : `Bot ${s.current} thinking…`} · {s.phase}
                </h2>}
            {s.lastRoll && <p className="dice">🎲 {s.lastRoll[0]} + {s.lastRoll[1]} = {s.lastRoll[0] + s.lastRoll[1]}</p>}
          </section>

          {myTurn && (
            <section className="controls">
              {s.phase === 'AWAIT_ROLL' && (
                <>
                  <button className="primary" onClick={() => act({ type: 'ROLL', dice: rollDice() })}>Roll dice</button>
                  <button onClick={() => act({ type: 'FORFEIT' })}>Forfeit</button>
                </>
              )}
              {s.phase === 'AWAIT_BUY' && (
                <>
                  <button className="primary" onClick={() => act({ type: 'BUY' })}>
                    Buy {P.board[s.pendingTitle!]!.name} ({P.board[s.pendingTitle!]!.base_price})
                  </button>
                  <button onClick={() => act({ type: 'DECLINE' })}>Decline</button>
                </>
              )}
              {s.phase === 'AWAIT_TAX' && (
                <>
                  <button onClick={() => act({ type: 'PAY_TAX', choice: 'flat' })}>Pay flat 200</button>
                  <button onClick={() => act({ type: 'PAY_TAX', choice: 'percent' })}>Pay 10% of worth</button>
                </>
              )}
              {s.phase === 'AWAIT_POST' && (
                <>
                  {buildable.map((id) => (
                    <button key={id} onClick={() => act({ type: 'BUILD', propertyId: id })}>
                      Build {P.board[id]!.name} (+{P.groups[P.board[id]!.group!]!.build_cost})
                    </button>
                  ))}
                  <button className="primary" onClick={() => act({ type: 'END_TURN' })}>End turn</button>
                </>
              )}
            </section>
          )}

          <section className="seats">
            {s.seats.map((p) => (
              <div key={p.id} className={`seat ${p.id === s.current ? 'active' : ''} ${p.bankrupt ? 'bust' : ''}`}>
                <div className="seat-hd">
                  <span className="dot" style={{ background: SEAT_COLORS[p.id] }} />
                  <strong>{p.id === HUMAN ? 'You' : `Bot ${p.id}`}</strong>
                  <span className="cash">{p.bankrupt ? 'bankrupt' : `${p.balance} sat`}</span>
                </div>
                <div className="deeds">
                  {ownedBy(s, p.id).map(({ space, title }) => (
                    <span key={space.id} className="deed" title={space.name}
                      style={{ background: GROUP_COLOR[space.group ?? ''] ?? '#ccc' }}>
                      {space.name.split(' ')[0]}{title.buildLevel > 0 ? `·${title.buildLevel}` : ''}{title.mortgaged ? '✗' : ''}
                    </span>
                  ))}
                </div>
              </div>
            ))}
            <div className="bank">Bank reserve: {s.bankReserve} sat</div>
          </section>

          <section className="log">
            <h3>Transcript</h3>
            <ol>{s.log.slice(-14).map((line, i) => <li key={i}>{line}</li>)}</ol>
          </section>

          <ChatPanel />
        </aside>
      </div>
    </div>
  );
}
