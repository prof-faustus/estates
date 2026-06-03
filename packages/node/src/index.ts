/**
 * @estates/node — the native node adapter (no third-party REST). It speaks your
 * own BSV node's JSON-RPC to BROADCAST a move and to fetch a real SPV proof
 * (`gettxoutproof` → a CMerkleBlock), which it parses into an @estates/spv proof
 * verified against the block header. This is what the native sidecar runs; the
 * (de)serialization is pure and tested offline, the RPC calls hit your node.
 */
import { serializeHeader, type BlockHeader, type MerkleProof } from '@estates/spv';
import { parsePartialMerkleTree, type PartialMerkleTree } from '@estates/merkleblock';

const fromHex = (h: string): Uint8Array => { if (typeof h !== 'string' || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('invalid hex'); const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; };
const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// ---- CMerkleBlock wire format (what gettxoutproof returns) ------------------
function readU32le(b: Uint8Array, o: number): number { return (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0; }

/** Parse an 80-byte block header. */
export function parseHeader(b: Uint8Array): BlockHeader {
  if (b.length < 80) throw new Error('header < 80 bytes');
  return { version: readU32le(b, 0), prevHash: b.slice(4, 36), merkleRoot: b.slice(36, 68), time: readU32le(b, 68), bits: readU32le(b, 72), nonce: readU32le(b, 76) };
}

function readVarint(b: Uint8Array, o: number): { value: number; size: number } {
  const f = b[o]!;
  if (f < 0xfd) return { value: f, size: 1 };
  if (f === 0xfd) return { value: b[o + 1]! | (b[o + 2]! << 8), size: 3 };
  if (f === 0xfe) return { value: readU32le(b, o + 1), size: 5 };
  return { value: Number(readU32le(b, o + 1)) + readU32le(b, o + 5) * 2 ** 32, size: 9 };
}
function varintBytes(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, (n >>> 8) & 0xff]);
  return new Uint8Array([0xfe, n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
}

/** BIP-37 flag bits ↔ bytes (LSB first within each byte). */
export function packFlags(bits: readonly number[]): Uint8Array {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) if (bits[i]) out[i >> 3]! |= 1 << (i & 7);
  return out;
}
export function unpackFlags(bytes: Uint8Array, count: number): number[] {
  const bits: number[] = [];
  for (let i = 0; i < count; i++) bits.push((bytes[i >> 3]! >> (i & 7)) & 1);
  return bits;
}

export interface MerkleBlock { readonly header: BlockHeader; readonly pmt: PartialMerkleTree }

/** Serialize a CMerkleBlock (header + txCount + hashes + packed flags). Hashes are
 *  written in internal byte order, exactly as the node emits them. */
export function serializeMerkleBlock(mb: MerkleBlock, flagBitsLen?: number): Uint8Array {
  const parts: Uint8Array[] = [serializeHeader(mb.header), new Uint8Array([mb.pmt.txCount & 0xff, (mb.pmt.txCount >>> 8) & 0xff, (mb.pmt.txCount >>> 16) & 0xff, (mb.pmt.txCount >>> 24) & 0xff])];
  parts.push(varintBytes(mb.pmt.hashes.length), ...mb.pmt.hashes);
  const flagBytes = packFlags(mb.pmt.flags);
  parts.push(varintBytes(flagBytes.length), flagBytes);
  void flagBitsLen;
  let len = 0; for (const p of parts) len += p.length;
  const out = new Uint8Array(len); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** Parse a CMerkleBlock (the bytes from gettxoutproof). */
export function parseMerkleBlock(bytes: Uint8Array): MerkleBlock {
  const header = parseHeader(bytes);
  let o = 80;
  const txCount = readU32le(bytes, o); o += 4;
  const hc = readVarint(bytes, o); o += hc.size;
  const hashes: Uint8Array[] = [];
  for (let i = 0; i < hc.value; i++) { hashes.push(bytes.slice(o, o + 32)); o += 32; }
  const fc = readVarint(bytes, o); o += fc.size;
  const flagBytes = bytes.slice(o, o + fc.value);
  // BIP-37 flag count is unknown a-priori; parse drives consumption, so supply
  // all available bits and let parsePartialMerkleTree consume what it needs.
  const flags = unpackFlags(flagBytes, fc.value * 8);
  return { header, pmt: { txCount, hashes, flags } };
}

/** Extract the SPV proof for `txid` (display order) from a CMerkleBlock hex. */
export function proofFromMerkleBlockHex(hex: string, txidDisplay: string): { header: BlockHeader; proof: MerkleProof } | null {
  const mb = parseMerkleBlock(fromHex(hex));
  const parsed = parsePartialMerkleTree(mb.pmt);
  const wantLeaf = toHex(fromHex(txidDisplay).reverse()); // display → internal
  const m = parsed.matched.find((x) => toHex(x.hash) === wantLeaf);
  return m ? { header: mb.header, proof: m.proof } : null;
}

// ---- JSON-RPC to your own node (native; no third-party REST) ----------------
export interface NodeRpc { readonly url: string; readonly user: string; readonly pass: string }
const basicAuth = (u: string, p: string): string => (typeof Buffer !== 'undefined' ? Buffer.from(`${u}:${p}`).toString('base64') : btoa(`${u}:${p}`));

export async function rpc<T>(node: NodeRpc, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(node.url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Basic ' + basicAuth(node.user, node.pass) },
    body: JSON.stringify({ jsonrpc: '1.0', id: 'estates', method, params }),
  });
  const j = (await res.json()) as { result?: T; error?: { message: string } };
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result as T;
}

/** Broadcast a signed move transaction to your node (native sendrawtransaction). */
export async function broadcast(node: NodeRpc, rawTxHex: string): Promise<string> { return rpc<string>(node, 'sendrawtransaction', [rawTxHex]); }
/** Fetch a real SPV proof for a confirmed move from your node, parsed + ready to verify. */
export async function getProof(node: NodeRpc, txidDisplay: string): Promise<{ header: BlockHeader; proof: MerkleProof } | null> {
  const hex = await rpc<string>(node, 'gettxoutproof', [[txidDisplay]]);
  return proofFromMerkleBlockHex(hex, txidDisplay);
}
