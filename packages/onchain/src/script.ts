/**
 * Minimal BSV (post-Genesis) script model for ESTATES on-chain objects.
 *
 * Data is carried as PUSHDATA in live, spendable script and consumed with
 * OP_DROP / OP_2DROP — never OP_RETURN. `serializeScript` THROWS if OP_RETURN
 * appears (defence in depth alongside the CI static ban). Timing is never
 * CLTV/CSV; maturity lives at the tx level (nLockTime/nSequence).
 *
 * Mirrors @bsv-poker/script-templates-ts conventions (PROTOCOL-BINDING.md).
 */
export const OP = {
  OP_0: 0x00,
  OP_PUSHDATA1: 0x4c,
  OP_PUSHDATA2: 0x4d,
  OP_PUSHDATA4: 0x4e,
  OP_RETURN: 0x6a, // defined so we can ban it; never emitted
  OP_DUP: 0x76,
  OP_2DROP: 0x6d,
  OP_DROP: 0x75,
  OP_EQUALVERIFY: 0x88,
  OP_SHA256: 0xa8,
  OP_HASH160: 0xa9,
  OP_CHECKSIG: 0xac,
} as const;

export const BANNED_OPCODES: readonly number[] = [OP.OP_RETURN];

export type ScriptItem = { readonly op: number } | { readonly push: Uint8Array };

export const op = (o: number): ScriptItem => ({ op: o });
export const push = (b: Uint8Array): ScriptItem => ({ push: b });

function pushBytes(out: number[], data: Uint8Array): void {
  const n = data.length;
  if (n < OP.OP_PUSHDATA1) out.push(n);
  else if (n <= 0xff) out.push(OP.OP_PUSHDATA1, n);
  else if (n <= 0xffff) out.push(OP.OP_PUSHDATA2, n & 0xff, (n >> 8) & 0xff);
  else out.push(OP.OP_PUSHDATA4, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff);
  for (const b of data) out.push(b);
}

/** Serialize a script to bytes. Throws on any banned opcode (OP_RETURN). */
export function serializeScript(items: readonly ScriptItem[]): Uint8Array {
  const out: number[] = [];
  for (const it of items) {
    if ('op' in it) {
      if (BANNED_OPCODES.includes(it.op)) {
        throw new Error(`serializeScript: banned opcode 0x${it.op.toString(16)} (OP_RETURN) is forbidden`);
      }
      out.push(it.op);
    } else {
      pushBytes(out, it.push);
    }
  }
  return Uint8Array.from(out);
}

export function scriptHex(items: readonly ScriptItem[]): string {
  return Buffer.from(serializeScript(items)).toString('hex');
}

/** True if the script would contain OP_RETURN (without throwing). */
export function containsOpReturn(items: readonly ScriptItem[]): boolean {
  return items.some((it) => 'op' in it && it.op === OP.OP_RETURN);
}

/** Standard P2PKH ownership predicate: DUP HASH160 <pkh> EQUALVERIFY CHECKSIG. */
export function p2pkh(ownerPkh: Uint8Array): ScriptItem[] {
  if (ownerPkh.length !== 20) throw new Error('p2pkh: ownerPkh must be 20 bytes (HASH160)');
  return [op(OP.OP_DUP), op(OP.OP_HASH160), push(ownerPkh), op(OP.OP_EQUALVERIFY), op(OP.OP_CHECKSIG)];
}
