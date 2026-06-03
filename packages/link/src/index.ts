/**
 * @estates/link — true IP-to-IP peer transport over real TCP sockets. Two peers
 * connect directly (no relay server), run the @estates/channel mutual-auth
 * handshake, and thereafter exchange length-prefixed, AES-256-GCM authenticated
 * frames carrying moves/chat. This is the native networking the sidecar runs;
 * because it speaks real sockets it is Node-side (the desktop spawns it and the
 * UI talks to it over loopback).
 *
 * Wire: each message is a 4-byte big-endian length prefix + JSON. The first
 * message is the handshake (Hello from the dialer, Ack from the listener); every
 * subsequent message is a sealed frame.
 */
import { createServer, connect as netConnect, type Server, type Socket } from 'node:net';
import { initiate, respond, complete, seal, openFrame, type Identity, type Session, type Hello, type Ack } from '@estates/channel';

export type { Identity } from '@estates/channel';

function writeMsg(sock: Socket, obj: unknown): void {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const len = Buffer.allocUnsafe(4); len.writeUInt32BE(body.length, 0);
  sock.write(Buffer.concat([len, body]));
}

/** Accumulate stream bytes and emit each complete length-prefixed message. */
function framedReader(sock: Socket, onMsg: (obj: any) => void): void {
  let buf = Buffer.alloc(0);
  sock.on('data', (chunk: Buffer) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      if (buf.length < 4) return;
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) return;
      const body = buf.subarray(4, 4 + len);
      buf = buf.subarray(4 + len);
      try { onMsg(JSON.parse(body.toString('utf8'))); } catch { /* drop malformed */ }
    }
  });
}

/** An authenticated, encrypted link to one peer. */
export class PeerLink {
  readonly peerIdPub: Uint8Array;     // the peer's secp256k1 identity (ECDH / wallet) pub
  readonly peerSignPub: Uint8Array;   // the peer's Ed25519 signing pub (vouched for in the handshake)
  private sock: Socket;
  private session: Session;
  private handlers: ((m: Uint8Array) => void)[] = [];
  private inbox: Uint8Array[] = []; // frames received before a handler was attached
  constructor(sock: Socket, session: Session) {
    this.sock = sock; this.session = session; this.peerIdPub = session.peerIdPub; this.peerSignPub = session.peerSignPub;
  }
  /** Route post-handshake frames (called by listen/connect once the session is up). */
  bind(): void {
    framedReader(this.sock, (o) => {
      if (o && o.t === 'frame' && o.f) {
        const pt = openFrame(this.session, o.f);
        if (!pt) return;
        if (this.handlers.length === 0) this.inbox.push(pt);
        else for (const h of this.handlers) h(pt);
      }
    });
  }
  send(plaintext: Uint8Array): void { writeMsg(this.sock, { t: 'frame', f: seal(this.session, plaintext) }); }
  onMessage(cb: (m: Uint8Array) => void): void {
    this.handlers.push(cb);
    if (this.inbox.length > 0) { const pending = this.inbox; this.inbox = []; for (const m of pending) cb(m); }
  }
  close(): void { this.sock.destroy(); }
}

/** Listen for inbound peers; each authenticated connection yields a PeerLink. */
export function listen(port: number, identity: Identity, onPeer: (link: PeerLink) => void): Promise<Server> {
  return new Promise((resolve) => {
    const server = createServer((sock) => {
      // first message must be the Hello; respond with Ack, then bind frames.
      let handshaken = false;
      let buf = Buffer.alloc(0);
      const onData = (chunk: Buffer): void => {
        buf = Buffer.concat([buf, chunk]);
        if (handshaken || buf.length < 4) return;
        const len = buf.readUInt32BE(0);
        if (buf.length < 4 + len) return;
        const msg = JSON.parse(buf.subarray(4, 4 + len).toString('utf8')) as { t: string; hello: Hello };
        buf = buf.subarray(4 + len);
        const r = msg.t === 'hello' ? respond(identity, msg.hello) : null;
        if (!r) { sock.destroy(); return; }
        writeMsg(sock, { t: 'ack', ack: r.ack });
        handshaken = true;
        sock.removeListener('data', onData);
        const link = new PeerLink(sock, r.session);
        // any bytes already buffered after the hello belong to frames
        link.bind();
        if (buf.length > 0) sock.emit('data', buf);
        onPeer(link);
      };
      sock.on('data', onData);
    });
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

/** Dial a peer at host:port and return the authenticated link. */
export function connect(host: string, port: number, identity: Identity): Promise<PeerLink> {
  return new Promise((resolve, reject) => {
    const sock = netConnect(port, host, () => {
      const { hello, pending } = initiate(identity);
      writeMsg(sock, { t: 'hello', hello });
      let buf = Buffer.alloc(0);
      const onData = (chunk: Buffer): void => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length < 4) return;
        const len = buf.readUInt32BE(0);
        if (buf.length < 4 + len) return;
        const msg = JSON.parse(buf.subarray(4, 4 + len).toString('utf8')) as { t: string; ack: Ack };
        buf = buf.subarray(4 + len);
        const session = msg.t === 'ack' ? complete(pending, msg.ack) : null;
        if (!session) { sock.destroy(); reject(new Error('handshake failed')); return; }
        sock.removeListener('data', onData);
        const link = new PeerLink(sock, session);
        link.bind();
        if (buf.length > 0) sock.emit('data', buf);
        resolve(link);
      };
      sock.on('data', onData);
    });
    sock.on('error', reject);
  });
}
