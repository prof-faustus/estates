import { useEffect, useReducer, useRef, useState } from 'react';
import { ChatRoom, HttpRelay, genPeer, type ChatMessage, type Peer } from '@estates/chat';
import { makeRelay } from './game';

/**
 * Table chat — end-to-end encrypted. YOU choose:
 *  - transport: Bitmessage-style built-in relay, or a direct IP/URL you enter
 *  - mode: broadcast to everyone, or 2-party ECDH to one member you pick
 * The relay only ever sees ciphertext; keys never leave this client.
 */
type Transport = 'bitmessage' | 'direct';
type Mode = 'broadcast' | '2party';

export function ChatPanel() {
  const [, force] = useReducer((x: number) => x + 1, 0);
  const [peer] = useState<Peer>(() => genPeer());
  const [transport, setTransport] = useState<Transport>('bitmessage');
  const [directUrl, setDirectUrl] = useState('');
  const [mode, setMode] = useState<Mode>('broadcast');
  const [to, setTo] = useState('');               // 2-party recipient address
  const [connected, setConnected] = useState(false);
  const [msgs, setMsgs] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState('');
  const roomRef = useRef<ChatRoom | null>(null);

  useEffect(() => () => roomRef.current?.disconnect(), []);

  function connect() {
    const relay = transport === 'direct' && directUrl.trim()
      ? new HttpRelay(directUrl.trim(), 'estates-table')   // direct IP/URL
      : makeRelay('estates-table');                        // built-in Bitmessage-style relay
    const room = new ChatRoom(relay, peer, `seat-${peer.address.slice(0, 6)}`);
    room.onMessage((m) => setMsgs((prev) => [...prev, m]));
    room.connect();
    room.join();
    roomRef.current = room;
    setConnected(true);
    setInterval(force, 600); // refresh member list
  }

  function send() {
    const text = draft.trim();
    const room = roomRef.current;
    if (!text || !room) return;
    if (mode === '2party' && to) room.postTo(to, text);   // 2-party ECDH
    else room.post(text);                                 // broadcast
    setDraft('');
  }

  const members = roomRef.current ? [...roomRef.current.members.values()] : [];

  return (
    <section className="chat">
      <h3>Table chat <span className="enc">🔒 encrypted</span></h3>
      {!connected ? (
        <div className="wtab">
          <label>transport
            <select value={transport} onChange={(e) => setTransport(e.target.value as Transport)}>
              <option value="bitmessage">Bitmessage-style (built-in)</option>
              <option value="direct">Direct IP/URL</option>
            </select>
          </label>
          {transport === 'direct' && <input placeholder="ws/http URL or IP" value={directUrl} onChange={(e) => setDirectUrl(e.target.value)} />}
          <label>mode
            <select value={mode} onChange={(e) => setMode(e.target.value as Mode)}>
              <option value="broadcast">Broadcast (everyone)</option>
              <option value="2party">2-party ECDH</option>
            </select>
          </label>
          <button className="primary" onClick={connect}>Join chat</button>
        </div>
      ) : (
        <>
          <div className="chat-status">you: <code>{peer.address.slice(0, 10)}…</code> · {members.length} member(s) · {transport === 'direct' ? 'direct' : 'bitmessage'}</div>
          {mode === '2party' && (
            <label className="chat-status">to
              <select value={to} onChange={(e) => setTo(e.target.value)}>
                <option value="">(pick a member)</option>
                {members.filter((m) => m.address !== peer.address).map((m) => <option key={m.address} value={m.address}>{m.name ?? m.address.slice(0, 8)}</option>)}
              </select>
            </label>
          )}
          <ol className="chat-log">
            {msgs.slice(-40).map((m, i) => <li key={i}><code>{m.from.slice(0, 6)}</code>: {m.text}</li>)}
          </ol>
          <div className="chat-input">
            <input value={draft} placeholder={mode === '2party' ? 'private message…' : 'message…'} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') send(); }} />
            <button onClick={send}>Send</button>
          </div>
        </>
      )}
    </section>
  );
}
