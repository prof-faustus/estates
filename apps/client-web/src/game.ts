/**
 * Client glue — the multiplayer controller + lobby discovery live in
 * @estates/table (exhaustively tested). Here we only add UI-only helpers.
 */
import type { GameState } from '@estates/engine';
export {
  P, NetTable, makeRelay, rollDice, botAction, identityFrom, gameIdentityFrom, gameIdFromChannel,
  LobbyClient, newAddress, buildable, mortgageable, unmortgageable, lastCard,
  LOBBY_CHANNEL,
} from '@estates/table';
export type { NetworkMode, TableView, SeatInfo, OpenTable, Identity } from '@estates/table';
import { P } from '@estates/table';

export const SEAT_COLORS = ['#e6194b', '#3cb44b', '#4363d8', '#f58231', '#911eb4', '#42d4f4'];
export const GROUP_COLOR: Record<string, string> = {
  Sienna: '#8d5524', Sky: '#aee1f9', Rose: '#f7a8c4', Amber: '#f5a623',
  Crimson: '#d0021b', Gold: '#f8e71c', Viridian: '#2e7d32', Indigo: '#283593',
  Rails: '#555', Utilities: '#bbb',
};

export function ownedBy(s: GameState, seatId: number) {
  return P.board
    .filter((sp) => (sp.type === 'property' || sp.type === 'station' || sp.type === 'utility') && s.titles[sp.id]?.owner === seatId)
    .map((sp) => ({ space: sp, title: s.titles[sp.id]! }));
}
