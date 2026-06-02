/**
 * Runnable ESTATES relay — an untrusted HTTP+SSE fan-out for table channels
 * (game actions + encrypted chat). It never sees plaintext or game logic; it
 * only orders and rebroadcasts opaque payloads per channel.
 *
 *   node --experimental-strip-types packages/chat/src/serve.ts [port]
 */
import { startRelayServer } from './server.ts';

const port = Number(process.argv[2] ?? 8788);
const s = await startRelayServer(port);
console.log(`ESTATES relay listening at ${s.url}  (use this as the relay URL)`);
process.on('SIGINT', () => { void s.close().then(() => process.exit(0)); });
