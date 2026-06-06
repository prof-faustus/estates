/**
 * lint-bans.ts — ESTATES static ban checks (BUILD-KICKOFF "Non-negotiable rules").
 *
 * FAILS THE BUILD (exit 1) if any produced source references:
 *   - OP_RETURN                         (data must be pushdata in live script + OP_DROP)
 *   - OP_CHECKLOCKTIMEVERIFY / CLTV     (timing is nLockTime only)
 *   - OP_CHECKSEQUENCEVERIFY / CSV      (timing is nSequence only)
 *   - branded / trademarked strings     (original, non-copyright content only)
 *
 * Mirrors bsv-poker's tools/lint-opreturn.ts source-scan and extends it to
 * CLTV/CSV and trademark strings. Runs with: node --experimental-strip-types.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..');

// Directories never scanned.
// `bin`/`obj` are .NET build output (generated; contain absolute paths with the
// repo's own folder name); `render-out` holds generated screenshots/profiles.
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'dist-app', 'build', '.vite', 'coverage', 'bin', 'obj', 'render-out']);

// Files/paths sanctioned to mention banned tokens (the ban machinery itself,
// the opcode table that must define them, the interpreter NO-OP, and tests
// that assert the bans). Matched against the repo-relative POSIX path.
const ALLOW = [
  /tools[/]lint-bans\.ts$/,
  /tools[/]ci\.ts$/,
  /[/]opcodes\.ts$/,
  /[/]interpreter\.ts$/,
  /[/]script\.ts$/, // the script model legitimately defines + bans OP_RETURN
  /\.test\.ts$/,
  /[/]bans\.test\.ts$/,
];

// NO-SERVER bans (ABSOLUTE): ESTATES is a TRUE peer-to-peer system in BOTH web and
// exe. A server of ANY kind — a relay, a store-and-forward, an HTTP/SSE endpoint, an
// RPC proxy — is forbidden and FAILS THE BUILD. The only networking allowed is direct
// peer-to-peer over `node:net` sockets (`@estates/link`, IP-to-IP, no relay) and the
// browser's own `fetch` straight to a player's OWN node/network (never our proxy).
// These bans are enforced in EVERY code file (incl. tests) — only this lint is exempt.
const SERVER_BANS: { name: string; re: RegExp }[] = [
  { name: "HTTP server module (node:http/https)", re: /\bnode:https?\b/ },
  { name: "HTTP server (createServer from node:http)", re: /from\s+['"]https?['"]/ },
  { name: "relay server entrypoint (startRelayServer)", re: /\bstartRelayServer\b/ },
  { name: "HTTP relay client/server (HttpRelay)", re: /\bHttpRelay\b/ },
  { name: "relay endpoint /publish", re: /\/publish\// },
  { name: "relay endpoint /subscribe", re: /\/subscribe\// },
  { name: "relay endpoint /history", re: /\/history\// },
  { name: "relay RPC proxy endpoint /rpc", re: /\/rpc\b/ },
];
const SERVER_BAN_EXEMPT = /tools[/\\]lint-bans\.ts$/;

// Opcode bans: textual opcode identifiers in produced source.
// Match the actual opcode identifiers that could appear in produced script
// (not the CLTV/CSV abbreviations, which legitimately appear in prose/docs).
const OPCODE_BANS: { name: string; re: RegExp }[] = [
  { name: 'OP_RETURN', re: /\bOP_RETURN\b/ },
  { name: 'OP_CHECKLOCKTIMEVERIFY (CLTV)', re: /\bOP_CHECKLOCKTIMEVERIFY\b/ },
  { name: 'OP_CHECKSEQUENCEVERIFY (CSV)', re: /\bOP_CHECKSEQUENCEVERIFY\b/ },
];

// Branded / trademarked strings that must never appear in game content.
// (Original ESTATES content replaces all of these.)
const BRANDED = [
  'monopoly', 'hasbro', 'parker brothers', 'rich uncle pennybags', 'mr. monopoly',
  'boardwalk', 'park place', 'marvin gardens', 'community chest', 'chance card',
  'get out of jail free', 'reading railroad', 'pennsylvania railroad',
  'b&o railroad', 'short line', 'electric company', 'water works', 'st. charles place',
  'baltic avenue', 'mediterranean avenue', 'free parking', 'go to jail',
];

// Browser-safety ban: these packages are bundled into the desktop webview
// (@estates/client-web's dependency closure). `Buffer` is a Node global that is
// UNDEFINED in the browser — a bare `Buffer.from(...)` builds fine but throws
// `ReferenceError: Buffer is not defined` at runtime (it crashed the chat panel).
// Use isomorphic hex/base64 instead. Matches actual usage `Buffer.` / `Buffer(`
// (not the word in comments, and not a guarded `globalThis...Buffer!.` fallback).
const BROWSER_BUNDLED = ['packages/chat/src/', 'packages/table/src/', 'packages/engine/src/', 'packages/params/src/', 'packages/turn/src/', 'packages/wallet/src/', 'packages/beacon/src/', 'packages/deck/src/', 'packages/channel/src/', 'apps/client-web/src/'];
const BUFFER_USE = /\bBuffer\s*[.(]/;

const CODE_EXT = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs']);
const CONTENT_EXT = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs', '.json']);

interface Hit { file: string; line: number; ban: string; text: string; }
const hits: Hit[] = [];

function allowed(rel: string): boolean {
  const posix = rel.split(sep).join('/');
  return ALLOW.some((re) => re.test(posix));
}

function walk(dir: string): void {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(entry)) walk(full);
      continue;
    }
    scan(full);
  }
}

function scan(full: string): void {
  const rel = relative(ROOT, full);
  const dot = full.lastIndexOf('.');
  const ext = dot >= 0 ? full.slice(dot) : '';
  const isCode = CODE_EXT.has(ext);
  const isContent = CONTENT_EXT.has(ext);
  if (!isCode && !isContent) return;

  const allLines = readFileSync(full, 'utf8').split(/\r?\n/);

  // NO-SERVER gate: enforced in EVERY code file (including tests) — only this lint is
  // exempt. A server of any kind anywhere is a fatal, build-failing violation.
  if (isCode && !SERVER_BAN_EXEMPT.test(rel)) {
    allLines.forEach((text, i) => {
      for (const b of SERVER_BANS) {
        if (b.re.test(text)) hits.push({ file: rel, line: i + 1, ban: `NO SERVER — ${b.name}`, text: text.trim() });
      }
    });
  }

  if (allowed(rel)) return;

  const lines = allLines;
  lines.forEach((text, i) => {
    if (isCode) {
      for (const b of OPCODE_BANS) {
        if (b.re.test(text)) hits.push({ file: rel, line: i + 1, ban: b.name, text: text.trim() });
      }
      const posix = rel.split(sep).join('/');
      if (BUFFER_USE.test(text) && BROWSER_BUNDLED.some((p) => posix.startsWith(p))) {
        hits.push({ file: rel, line: i + 1, ban: 'Buffer in browser-bundled code (use isomorphic hex/base64)', text: text.trim() });
      }
    }
    if (isContent) {
      const lower = text.toLowerCase();
      for (const brand of BRANDED) {
        if (lower.includes(brand)) {
          hits.push({ file: rel, line: i + 1, ban: `branded string "${brand}"`, text: text.trim() });
        }
      }
    }
  });
}

walk(ROOT);

if (hits.length > 0) {
  console.error(`\n✘ lint-bans: ${hits.length} violation(s) — build FAILED\n`);
  for (const h of hits) {
    console.error(`  ${h.file}:${h.line}  [${h.ban}]`);
    console.error(`      ${h.text.slice(0, 120)}`);
  }
  console.error('\nOP_RETURN / CLTV / CSV are banned; on-chain data is pushdata + OP_DROP,');
  console.error('timing is nLockTime/nSequence, and all content must be original.\n');
  process.exit(1);
}

console.log('✓ lint-bans: no OP_RETURN / CLTV / CSV / branded strings found.');
