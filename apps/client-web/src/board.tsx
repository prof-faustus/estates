import type { GameState } from '@estates/engine';
import { P, SEAT_COLORS, GROUP_COLOR } from './game';

const N = 11;            // 11×11 perimeter
const CELL = 62;
const SIZE = N * CELL;

/** Grid cell (col,row) for a board index, GO at bottom-right going counter-clockwise. */
function cell(i: number): { x: number; y: number } {
  if (i <= 10) return { x: 10 - i, y: 10 };            // bottom row (0..10)
  if (i <= 20) return { x: 0, y: 10 - (i - 10) };      // left col (11..20)
  if (i <= 30) return { x: i - 20, y: 0 };             // top row (21..30)
  return { x: 10, y: i - 30 };                         // right col (31..39)
}

export function Board({ s }: { s: GameState }) {
  return (
    <svg width={SIZE} height={SIZE} viewBox={`0 0 ${SIZE} ${SIZE}`} className="board">
      <rect x={0} y={0} width={SIZE} height={SIZE} fill="#f4f1e8" stroke="#222" />
      {P.board.map((sp) => {
        const c = cell(sp.id);
        const x = c.x * CELL;
        const y = c.y * CELL;
        const title = s.titles[sp.id];
        const owner = title?.owner ?? null;
        const band = sp.group ? GROUP_COLOR[sp.group] ?? '#ccc' : '#ddd';
        return (
          <g key={sp.id}>
            <rect x={x} y={y} width={CELL} height={CELL} fill="#fff" stroke="#333" strokeWidth={1} />
            {(sp.type === 'property' || sp.type === 'station' || sp.type === 'utility') && (
              <rect x={x} y={y} width={CELL} height={10} fill={band} />
            )}
            <text x={x + CELL / 2} y={y + 26} textAnchor="middle" fontSize={6.5} fill="#111">
              {sp.name.length > 13 ? sp.name.slice(0, 12) + '…' : sp.name}
            </text>
            {sp.base_price !== undefined && (
              <text x={x + CELL / 2} y={y + 38} textAnchor="middle" fontSize={7} fill="#555">
                {sp.base_price}
              </text>
            )}
            {owner !== null && (
              <circle cx={x + CELL - 9} cy={y + CELL - 9} r={5} fill={SEAT_COLORS[owner] ?? '#000'} stroke="#222" />
            )}
            {title && title.buildLevel > 0 && (
              <text x={x + 9} y={y + CELL - 6} fontSize={8} fill="#0a0">{'▲'.repeat(Math.min(title.buildLevel, 4))}{title.buildLevel === 5 ? '★' : ''}</text>
            )}
            {title?.mortgaged && (
              <text x={x + CELL / 2} y={y + CELL - 6} textAnchor="middle" fontSize={6} fill="#b00">MORTGAGED</text>
            )}
          </g>
        );
      })}
      {/* seat tokens */}
      {s.seats.filter((p) => !p.bankrupt).map((p, idx) => {
        const c = cell(p.position);
        const x = c.x * CELL + 14 + (idx % 3) * 12;
        const y = c.y * CELL + CELL / 2 + Math.floor(idx / 3) * 12;
        return <circle key={p.id} cx={x} cy={y} r={6} fill={SEAT_COLORS[p.id] ?? '#000'} stroke="#fff" strokeWidth={1.5} />;
      })}
      <text x={SIZE / 2} y={SIZE / 2 - 8} textAnchor="middle" fontSize={34} fill="#cdb" fontWeight="bold">ESTATES</text>
      <text x={SIZE / 2} y={SIZE / 2 + 18} textAnchor="middle" fontSize={11} fill="#999">dealerless · on-chain · BSV</text>
    </svg>
  );
}
