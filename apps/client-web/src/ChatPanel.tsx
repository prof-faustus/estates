import { useEffect, useRef, useState } from 'react';
import { ChatRoom, HttpRelay, InMemoryRelay, genPeer, type ChatMessage, type Peer } from '@estates/chat';

/**
 * Table chat — broadcast-encrypted (multi-recipient ECIES over secp256k1) and
 * carried over an untrusted relay. Leave the relay URL blank for local
 * (in-process) practice; enter a relay URL to chat live with other players.
 * The relay only ever sees ciphertext; keys never leave this client.
 */
export function ChatPanel() {
  const [peer] = useState<Peer>(() => genPeer());
  const [url, setUrl] = useState('');
  const [connected, setConnected] = useState(false);
  const [members, setMembers] = useState(0);
  const [msgs, setMsgs] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState('');
  const roomRef = useRef<ChatRoom | null>(null);

  useEffect(() => () => roomRef.current?.disconnect(), []);

  function connect() {
    const relay = url.trim() ? new HttpRelay(url.trim(), 'estates-table') : new InMemoryRelay();
    const room = new ChatRoom(relay, peer, `seat-${peer.address.slice(0, 6)}`);
    room.onMessage((m) => setMsgs((prev) => [...prev, m]));
    room.connect();
    room.join();
    roomRef.current = room;
    setConnected(true);
    const tick = setInterval(() => setMembers(room.members.size), 500);
    return () => clearInterval(tick);
  }

  function send() {
    const text = draft.trim();
    if (!text || !roomRef.current) return;
    roomRef.current.post(text);
    setDraft('');
  }

  return (
    <section className="chat">
      <h3>Table chat <span className="enc">🔒 broadcast-encrypted</span></h3>
      {!connected ? (
        <div className="chat-connect">
          <input
            placeholder="relay URL (blank = local practice)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button className="primary" onClick={connect}>Join chat</button>
        </div>
      ) : (
        <>
          <div className="chat-status">
            you: <code>{peer.address.slice(0, 10)}…</code> · members: {members} · {url ? 'online' : 'local'}
          </div>
          <ol className="chat-log">
            {msgs.slice(-40).map((m, i) => (
              <li key={i}>
                <code>{m.from.slice(0, 6)}</code>: {m.text}
              </li>
            ))}
          </ol>
          <div className="chat-input">
            <input
              value={draft}
              placeholder="message…"
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') send(); }}
            />
            <button onClick={send}>Send</button>
          </div>
        </>
      )}
    </section>
  );
}
