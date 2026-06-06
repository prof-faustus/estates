// PLAN P0 — guard rails. Written from scratch. This fails the build on ANY violation of the
// master plan's hard rules, so no later phase can regress. Every rule here maps to a PLAN.md
// clause and an audit finding. Run before typecheck/test/build in CI.
//
// It scans the product source (packages/* + apps/native, EXCLUDING tests and this tools dir) for:
//   - servers / relays                         (PLAN §1.7  — pure P2P, no server)
//   - OP_RETURN / CLTV / CSV in emitted script (PLAN §6, audit — pushdata+OP_DROP only)
//   - third-party NuGet/crypto libraries        (PLAN §1.2 — Microsoft-only, in-tree)
//   - WIF printed to stdout / CLI argv surface  (PLAN §1.9, audit 2.1/9.2)
//   - Ed25519 (banned curve)                    (PLAN — secp256k1 only)
//   - RFC-6979 / deterministic-nonce signing    (PLAN §2 — rejected, user's method only)
//   - BIP32/39/44 (BTC-Core)                    (PLAN — BSV only, Type-42)
//   - OP_TRUE "covenant" (anyone-spend)          (audit 4.1 — never a fake covenant)
//
// A hit prints file:line and the violated PLAN clause, and exits non-zero. Zero hits = pass.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dirname ?? '.', '..');
const SKIP_DIR = new Set(['node_modules', '.git', 'dist', 'bin', 'obj', 'coverage', 'tools', 'target']);
const SKIP_FILE = /(\.test\.|\.spec\.|guards\.ts$)/;

// `except` (optional) exempts files whose path matches it — used ONLY for the canonical
// opcode/ban-definition module, which must NAME the banned opcodes to ban them.
interface Rule { readonly clause: string; readonly re: RegExp; readonly why: string; readonly except?: RegExp }
const RULES: readonly Rule[] = [
  // No CENTRAL relay/ordering/HTTP server. The direct-peer TCP transport (link/src/index.ts) is
  // exempt: a peer's own `node:net` listener accepts ONLY direct mutually-authenticated links and
  // stores/forwards nothing — that is pure P2P (peers both dial and accept), not central infra.
  { clause: 'PLAN §1.7', re: /\b(createServer|http\.Server|startRelayServer|HttpRelay|express\(\))/, why: 'no server/relay — pure P2P', except: /link[\\/]src[\\/]index\.ts$/ },
  // OP_RETURN/CLTV/CSV may not be EMITTED. The opcode/ban authority (onchain/src/script.ts) is
  // exempt — it defines OP_RETURN expressly to forbid it (BANNED_OPCODES, serializeScript throws).
  { clause: 'PLAN §6',   re: /\bOP_RETURN\b|\bOP_CHECKLOCKTIMEVERIFY\b|\bOP_CHECKSEQUENCEVERIFY\b|\bCLTV\b|\bCSV\b/, why: 'no OP_RETURN/CLTV/CSV', except: /onchain[\\/]src[\\/]script\.ts$/ },
  // Real third-party crypto LIBRARIES only — not the bareword 'secp256k1' (a curve label) and not
  // node:crypto's namedCurve. The in-tree core lives in @estates/keys.
  { clause: 'PLAN §1.2', re: /BouncyCastle|bcprov|@noble\/|from ['"]elliptic['"]|from ['"]secp256k1['"]|require\(['"]secp256k1['"]\)|\btweetnacl\b/, why: 'no third-party crypto library (Microsoft-only / in-tree)' },
  { clause: 'PLAN §1.9', re: /toWif\s*\(\s*\)[^;]*console|console\.[a-z]+\([^)]*wif/i, why: 'no WIF to stdout' },
  { clause: 'PLAN §1.9', re: /process\.argv|args\.slice\(2\)|--funder-wif|--rpc-(user|pass)/, why: 'no CLI option/flag surface' },
  // Real Ed25519 USAGE — the @noble/ed25519 lib, a quoted 'ed25519' keyType literal, or an ed25519
  // curve call — NOT the prose word "Ed25519" in a comment explaining the secp256k1-only design.
  { clause: 'PLAN keys', re: /@noble\/ed25519|['"]ed25519['"]|\bed25519\.(sign|verify|getPublicKey)\b|Rfc8032/, why: 'Ed25519 banned — secp256k1 only' },
  { clause: 'PLAN §2',   re: /rfc-?6979|rfc6979|deterministic.{0,12}nonce/i, why: 'RFC-6979/deterministic-nonce signing rejected — user method only' },
  { clause: 'PLAN keys', re: /\bbip-?32\b|\bbip-?39\b|\bbip-?44\b|mnemonic|Bitcoin seed/i, why: 'BIP/BTC-Core key schemes banned — Type-42 only' },
  { clause: 'audit 4.1', re: /OP_TRUE\b.{0,40}covenant|covenant.{0,40}OP_TRUE/i, why: 'no fake anyone-spend "covenant"' },
];

const SCAN = [join(ROOT, 'packages'), join(ROOT, 'apps', 'native')];

function* files(dir: string): Generator<string> {
  let entries: string[];
  try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (SKIP_DIR.has(e)) continue;
    const p = join(dir, e);
    const s = statSync(p);
    if (s.isDirectory()) yield* files(p);
    else if (/\.(ts|cs|tsx)$/.test(e) && !SKIP_FILE.test(e)) yield p;
  }
}

let hits = 0;
for (const dir of SCAN) {
  for (const f of files(dir)) {
    const lines = readFileSync(f, 'utf8').split('\n');
    lines.forEach((line, i) => {
      const trimmed = line.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) return; // skip comment lines
      // strip a trailing inline comment (` // …`) so prose in comments is not scanned as code; the
      // required leading whitespace avoids truncating `https://` or other `//` inside a string.
      const code = line.replace(/\s+\/\/.*$/, '');
      for (const r of RULES) {
        if (r.except && r.except.test(f)) continue;     // canonical opcode/ban authority is exempt
        if (r.re.test(code)) { hits++; console.error(`${f}:${i + 1}  [${r.clause}] ${r.why}\n    ${line.trim().slice(0, 120)}`); }
      }
    });
  }
}

if (hits > 0) { console.error(`\nGUARDS FAILED: ${hits} plan-violation(s).`); process.exit(1); }
console.log('GUARDS PASS: no plan violations in the product source.');
