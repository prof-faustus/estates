// ESTATES RED TEAM — fire the headline attacks at the REAL package source and
// prove each boundary defends (rejects + never throws + never hangs). Run:
//   node --experimental-strip-types tools/redteam.mjs
// This is the adversary's view: a funded attacker spending a billion dollars to
// steal one satoshi, hammering every untrusted-input boundary.
// @noble isn't hoisted to the repo root; resolve it from a package that deps it.
import * as secp from '../packages/channel/node_modules/@noble/secp256k1/index.js';
import { sha256 } from '../packages/channel/node_modules/@noble/hashes/sha256.js';
import { hmac } from '../packages/channel/node_modules/@noble/hashes/hmac.js';
import { bytesToHex, concatBytes } from '../packages/channel/node_modules/@noble/hashes/utils.js';

import { genIdentity, respond, complete } from '../packages/channel/src/index.ts';
import { deserializeTx } from '../packages/tx/src/index.ts';
import { decodeEnvelope } from '../packages/net/src/index.ts';
import { decodeFrame } from '../packages/sidecar/src/index.ts';
import { verifyInput } from '../packages/scriptvm/src/index.ts';
import { genCardKey, sealTo, commit, openCard } from '../packages/deck/src/index.ts';
import { decodeActionCommit } from '../packages/txmap/src/index.ts';
import { parseMerkleBlock } from '../packages/node/src/index.ts';
import { audit } from '../packages/audit/src/index.ts';
import { decodeSigned } from '../packages/table/src/index.ts';

secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));
const enc = new TextEncoder();
const frame = (o) => enc.encode(JSON.stringify(o));
const results = [];
const T0 = Date.now();
// an attack "passes" (defended) iff the call neither throws nor hangs AND the
// verdict function says the result is a safe rejection.
function attack(name, fn, defended) {
  const t = Date.now();
  let threw = null, val;
  try { val = fn(); } catch (e) { threw = e; }
  const ms = Date.now() - t;
  const ok = threw === null && ms < 2000 && defended(val);
  results.push({ name, ok, ms, detail: threw ? `THREW ${threw.message}` : (ms >= 2000 ? `HUNG ${ms}ms` : 'rejected') });
}

// 1) channel — a validly-SIGNED Hello carrying an OFF-CURVE ephemeral key.
//    A naive responder runs ECDH on it and crashes (unauthenticated remote DoS).
{
  const eve = genIdentity(), bob = genIdentity();
  const offEph = new Uint8Array(33); offEph[0] = 0x02; offEph.fill(0xff, 1);
  const nonce = new Uint8Array(32).fill(7);
  const H = (...p) => sha256(concatBytes(...p));
  const sig = secp.sign(H(enc.encode('hello'), offEph, nonce, eve.signPub), eve.priv).toCompactRawBytes();
  const hello = { idPub: bytesToHex(eve.pub), ephPub: bytesToHex(offEph), nonce: bytesToHex(nonce), signPub: bytesToHex(eve.signPub), sig: bytesToHex(sig) };
  attack('channel: off-curve ephemeral DoS (real signature)', () => respond(bob, hello), (v) => v === null);
  attack('channel: garbage/null handshake', () => complete({ id: eve, ephPriv: eve.priv, ephPub: eve.pub, nonce }, null), (v) => v === null);
}

// 2) node/merkleblock — a 2^31 txCount (hangs a naive treeHeight) + a huge varint
//    hash-count with no backing bytes (billion-slice memory DoS).
{
  const hdr = new Uint8Array(80);
  const big = new Uint8Array([...hdr, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00]); // txCount = 0x80000000
  attack('merkleblock: 2^31 txCount hang/stack-overflow', () => parseMerkleBlock(big), (v) => v === null);
  const huge = new Uint8Array([...hdr, 99, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // varint hashCount = huge
  attack('merkleblock: billion-slice varint memory DoS', () => parseMerkleBlock(huge), (v) => v === null);
}

// 3) audit — a 1e9-seat genesis (allocates a billion seats before any try/catch).
attack('audit: 1e9-seat genesis allocation DoS', () =>
  audit({ params_version: 'x', genesis: { network: 'regtest', seatCount: 1_000_000_000, bankReserve: 0 }, entries: [], finalHash: '' }),
  (v) => v && v.ok === false);

// 4) sidecar — a signed move with an arbitrary/unknown action (engine-driver bypass)
//    and out-of-range dice.
attack('sidecar: arbitrary action injection', () => decodeFrame(frame({ t: 'move', action: { type: '__proto__' }, sig: 'cc'.repeat(64) })), (v) => v === null);
attack('sidecar: out-of-range ROLL dice', () => decodeFrame(frame({ t: 'move', action: { type: 'ROLL', dice: [9, 9] }, sig: 'cc'.repeat(64) })), (v) => v === null);

// 5) net — a hostile relay envelope: bad seq, non-array commits, bad hex (fromHex throw).
attack('net: 1e12 seq', () => decodeEnvelope(frame({ seq: 1e12, entry: { kind: 'action', action: { type: 'BUY' } } })), (v) => v === null);
attack('net: roll with non-hex commit (fromHex throw)', () => decodeEnvelope(frame({ seq: 0, entry: { kind: 'roll', commits: [{ seat: 0, c: 'zz' }], reveals: [], dice: [1, 1] } })), (v) => v === null);

// 6) scriptvm — a non-push scriptSig + a banned opcode lock + garbage DER.
attack('scriptvm: non-push scriptSig', () => verifyInput({ version: 1, inputs: [{ prevTxid: 'ab'.repeat(32), prevVout: 0, scriptSig: new Uint8Array([0x76]), sequence: 0 }], outputs: [], lockTime: 0 }, 0, { value: 1, script: new Uint8Array([0x76, 0xa9]) }), (v) => v && v.ok === false);
attack('scriptvm: truncated PUSHDATA2 (claims 65535)', () => verifyInput({ version: 1, inputs: [{ prevTxid: 'ab'.repeat(32), prevVout: 0, scriptSig: new Uint8Array([0x4d, 0xff, 0xff, 1]), sequence: 0 }], outputs: [], lockTime: 0 }, 0, { value: 1, script: new Uint8Array(1) }), (v) => v && v.ok === false);

// 7) deck — a MALICIOUS minter who committed+sealed a malformed face.
{
  const holder = genCardKey();
  const blind = new Uint8Array(32).fill(9);
  const garbage = new Uint8Array([0xff, 0xff, 0xff]);
  const card = { tableId: '11'.repeat(32), cardPub: bytesToHex(genCardKey().pub), commitment: commit(garbage, blind), sealed: sealTo(holder.pub, garbage) };
  attack('deck: malicious minter malformed face', () => openCard(card, holder.priv, blind, '11'.repeat(32)), (v) => v === null);
}

// 8) txmap — a tagged-but-garbage on-chain commitment (truncated/out-of-range).
attack('txmap: BUILD propertyId 99 (out of range)', () => { try { decodeActionCommit(new Uint8Array([...enc.encode('ESTATES-MOVE-v1'), 0, 0, 0, 0, 0, 5, 0, 0, 0, 99])); return 'NO-THROW'; } catch { return 'REJECTED'; } }, (v) => v === 'REJECTED');

// 9) tx — a hostile raw transaction: input count varint claims billions.
attack('tx: deserializeTx billion-input varint', () => deserializeTx(new Uint8Array([0x01, 0, 0, 0, 0xfe, 0xff, 0xff, 0xff, 0xff])), (v) => v === null);

// 10) table — a validly-shaped 'start' carrying a 1e9 seatCount (engine alloc DoS).
attack('table: decodeSigned 1e9 seatCount start', () => decodeSigned(frame({ kind: 'start', by: 'h', config: { network: 'regtest', seatCount: 1e9, bankReserve: 0 }, seatMap: [], id: 'x', signPub: 'aa'.repeat(32), sig: 'bb'.repeat(64) })), (v) => v === null);

// 11) MEGA-FUZZ — 200k random byte blobs at every byte decoder; zero may throw/hang.
{
  let rng = 0xC0FFEE >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  const decs = [deserializeTx, decodeEnvelope, decodeFrame, parseMerkleBlock];
  let threw = 0; const t = Date.now();
  for (let i = 0; i < 200_000; i++) {
    const n = rand() % 64; const b = new Uint8Array(n); for (let k = 0; k < n; k++) b[k] = rand() & 0xff;
    const d = decs[rand() % decs.length];
    try { d(b); } catch { threw++; }
  }
  const ms = Date.now() - t;
  results.push({ name: `MEGA-FUZZ: 200k random blobs × ${decs.length} byte decoders`, ok: threw === 0 && ms < 15000, ms, detail: threw === 0 ? 'zero throws' : `${threw} THREW` });
}

// ---- verdict ----------------------------------------------------------------
console.log('\n  ESTATES RED TEAM — attacker hammering every untrusted-input boundary\n');
let pass = 0;
for (const r of results) {
  console.log(`  [${r.ok ? 'DEFENDED' : ' BREACH '}] ${r.name}  (${r.ms}ms, ${r.detail})`);
  if (r.ok) pass++;
}
console.log(`\n  ${pass}/${results.length} attacks DEFENDED in ${Date.now() - T0}ms.`);
if (pass !== results.length) { console.log('\n  *** BREACH — a boundary failed. ***'); process.exit(1); }
console.log('\n  No crash, no hang, no forged state. Every boundary held.\n');
