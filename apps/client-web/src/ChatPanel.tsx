import { useEffect, useReducer, useRef, useState } from 'react';
import { ChatRoom, HttpRelay, genPeer, peerFrom, type ChatMessage, type Peer } from '@estates/chat';
import { Wallet, type Network } from '@estates/wallet';
import { makeRelay } from './game';

/**
 * Table chat — end-to-end encrypted, ZERO-FRICTION.
 *  - identity: YOUR OWN wallet key (its Bitmessage address = ripemd160(sha256(pub))
 *    of the same key that signs your moves). Falls back to a throwaway only if the
 *    WIF is missing/invalid.
 *  - it AUTO-JOINS the table channel on mount, so every window discovers every
 *    other member immediately — you just type and send.
 *  - mode: broadcast to everyone, or 2-party ECDH to one member you pick.
 *  - transport: built-in Bitmessage-style relay, or a direct IP/URL you enter.
 * The relay only ever sees ciphertext; keys never leave this client.
 */
type Mode = 'broadcast' | '2party';

/** The chat peer derived from the player's wallet key (throwaway only if invalid). */
function chatPeer(wif: string | undefined, network: Network): Peer {
  if (wif) { try { return peerFrom(new Uint8Array(Wallet.fromWif(wif, network).key.toArray('be', 32))); } catch { /* fall through */ } }
  return genPeer();
}

export function ChatPanel({ channel = 'estates-table', wif, network = 'regtest', directUrl = '' }: { channel?: string; wif?: string; network?: Network; directUrl?: string }) {
  const [, force] = useReducer((x: number) => x + 1, 0);
  const [peer] = useState<Peer>(() => chatPeer(wif, network));
  const [mode, setMode] = useState<Mode>('broadcast');
  const [to, setTo] = useState('');               // 2-party recipient address
  const [msgs, setMsgs] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState('');
  const roomRef = useRef<ChatRoom | null>(null);

  // Auto-join the channel on mount (and re-join if the channel changes). No
  // button: members must discover each other for a broadcast to reach anyone.
  useEffect(() => {
    const relay = directUrl.trim() ? new HttpRelay(directUrl.trim(), channel) : makeRelay(channel);
    const room = new ChatRoom(relay, peer, `seat-${peer.address.slice(0, 6)}`);
    room.onMessage((m) => setMsgs((prev) => [...prev, m]));
    room.connect();
    room.join();
    // Re-announce a few times so a peer that joins slightly later still learns us
    // (joins are store-and-forward, but this also covers a relay that just came up).
    const reann = setInterval(() => room.join(), 4000);
    const refresh = setInterval(force, 800); // refresh member list
    roomRef.current = room;
    // Cleanup MUST NOT broadcast leave(): React StrictMode double-mounts in dev
    // (and `tauri dev` runs the dev build), so the throwaway first mount would
    // broadcast a `leave` that every other peer applies — wrongly removing us
    // from their member set and silently breaking the whole chat. Just stop our
    // own loops/subscription; a genuinely departed peer is harmless to leave in
    // others' lists (you'd just encrypt to a key nobody reads).
    return () => { clearInterval(reann); clearInterval(refresh); room.disconnect(); if (roomRef.current === room) roomRef.current = null; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [channel, directUrl]);

  function send() {
    const text = draft.trim();
    const room = roomRef.current;
    if (!text || !room) return;
    if (mode === '2party' && to) room.postTo(to, text);   // 2-party ECDH
    else room.post(text);                                 // broadcast to all known members
    setDraft('');
  }

  const members = roomRef.current ? [...roomRef.current.members.values()] : [];
  const others = members.filter((m) => m.address !== peer.address);

  return (
    <section className="chat">
      <h3>Table chat <span className="enc">🔒 encrypted</span></h3>
      <div className="chat-status">
        you: <code>{peer.address.slice(0, 10)}…</code> · {members.length} member(s)
        {others.length === 0 && <em> · waiting for another player to join…</em>}
      </div>
      <label className="chat-status">mode
        <select value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
          <option value="broadcast">Broadcast (everyone)</option>
          <option value="2party">2-party ECDH</option>
        </select>
        {mode === '2party' && (
          <select value={to} onChange={(e) => setTo(e.target.value)}>
            <option value="">(pick a member)</option>
            {others.map((m) => <option key={m.address} value={m.address}>{m.name ?? m.address.slice(0, 8)}</option>)}
          </select>
        )}
      </label>
      <ol className="chat-log">
        {msgs.slice(-40).map((m, i) => <li key={i}><code>{m.from.slice(0, 6)}</code>: {m.text}</li>)}
      </ol>
      <div className="chat-input">
        <input value={draft} placeholder={mode === '2party' ? 'private message…' : 'message…'} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') send(); }} />
        <button onClick={send}>Send</button>
      </div>
    </section>
  );
}
