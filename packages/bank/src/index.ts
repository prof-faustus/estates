/**
 * @estates/bank — the bank as a ROLE, not an operator.
 *
 * v1 (D-BANK-ENFORCE): bank UTXOs (the sats reserve + unsold 1-sat NFTs) are
 * guarded by an M-of-N threshold over the seat keys. Honest seats co-sign only
 * a spend they certify as a core-legal action (purchase / salary / payout /
 * tax-collect). Trust = honest quorum (stated). The covenant upgrade
 * (sighash-preimage introspection) removes the quorum assumption later.
 *
 * Also builds the genesis/setup tx (tx-nft §2): one root-of-provenance tx that
 * fixes the network mode, mints the 1-sat title + Reprieve NFTs to the bank,
 * funds each seat's starting balance and the bank reserve, and carries the
 * table parameters + beacon seed as pushdata in live, spendable script.
 */
import { createHash, createVerify, type KeyObject } from 'node:crypto';
import { loadParams, type EstatesParams } from '@estates/params';
import {
  nftOutput, paymentOutput, push, op, OP, serializeScript, gameTag,
  type TxOutput, type TitleState, type Outpoint,
} from '@estates/onchain';
import { sighashPreimage, signInput, type Tx, type TxInput, type KeyPair } from '@estates/trade';

// Trustless covenant bank (D-BANK-ENFORCE upgrade) + banker role.
export * from './covenant.ts';

const P: EstatesParams = loadParams();
const GROUP_IDS = Object.keys(P.groups);
const groupOrdinal = (g: string): number => Math.max(0, GROUP_IDS.indexOf(g));

// ---------------------------------------------------------------------------
// M-of-N bank-spend guard
// ---------------------------------------------------------------------------

export interface BankPolicy {
  readonly seatPubkeys: readonly KeyObject[]; // the N seat public keys
  readonly threshold: number;                 // M
}

function hash160(b: Uint8Array): Uint8Array {
  const s = createHash('sha256').update(b).digest();
  return new Uint8Array(createHash('ripemd160').update(s).digest());
}
function pubDer(k: KeyObject): Uint8Array { return new Uint8Array(k.export({ format: 'der', type: 'spki' })); }
function eq(a: Uint8Array, b: Uint8Array): boolean { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!; return d === 0; }

/** P2PKH hash for a bank/seat public key (for output addressing). */
export function pkhOf(k: KeyObject): Uint8Array { return hash160(pubDer(k)); }

export interface SeatSignature { readonly pub: KeyObject; readonly sig: Uint8Array; }

/** A seat signs a bank spend over input 0's SIGHASH_ALL preimage. */
export function signBankSpend(tx: Tx, key: KeyPair): Uint8Array {
  return signInput(tx, 0, key);
}

export interface BankCheck { readonly valid: boolean; readonly count: number; readonly reason: string; }

/**
 * Verify an M-of-N bank spend: count DISTINCT seat keys (from the policy) whose
 * signature verifies over input 0's preimage. Valid iff ≥ threshold.
 */
export function verifyBankSpend(tx: Tx, sigs: readonly SeatSignature[], policy: BankPolicy): BankCheck {
  const seatDers = policy.seatPubkeys.map(pubDer);
  const preimage = sighashPreimage(tx, 0);
  const seen = new Set<number>();
  for (const { pub, sig } of sigs) {
    const der = pubDer(pub);
    const idx = seatDers.findIndex((d) => eq(d, der));
    if (idx < 0 || seen.has(idx)) continue; // not a seat key, or duplicate signer
    const v = createVerify('SHA256'); v.update(preimage); v.end();
    if (v.verify(pub, sig)) seen.add(idx);
  }
  const count = seen.size;
  return { valid: count >= policy.threshold, count, reason: count >= policy.threshold ? `${count}-of-${policy.seatPubkeys.length} ≥ ${policy.threshold}` : `only ${count} valid seat signatures, need ${policy.threshold}` };
}

/** A core-legal bank action; seats certify the tx outputs match before signing. */
export type BankAction =
  | { kind: 'purchase'; buyerPkh: Uint8Array; bankPkh: Uint8Array; price: number; nft: TitleState }
  | { kind: 'salary' | 'payout'; seatPkh: Uint8Array; amount: number }
  | { kind: 'collect'; bankPkh: Uint8Array; amount: number };

/** The canonical outputs a legal bank action must produce (seats certify these). */
export function legalOutputs(a: BankAction): TxOutput[] {
  switch (a.kind) {
    // buyer receives the 1-sat NFT; the price flows to the bank reserve
    case 'purchase': return [nftOutput(a.nft, a.buyerPkh), paymentOutput(a.price, a.bankPkh)];
    // bank pays a seat (salary / payout)
    case 'salary': case 'payout': return [paymentOutput(a.amount, a.seatPkh)];
    // a seat pays the bank (tax / fee) — reserve receives the sats
    case 'collect': return [paymentOutput(a.amount, a.bankPkh)];
  }
}

/** True if a proposed spend's outputs match the certified legal action. */
export function certify(tx: Tx, expected: readonly TxOutput[]): boolean {
  if (tx.outputs.length !== expected.length) return false;
  return tx.outputs.every((o, i) => o.satoshis === expected[i]!.satoshis && eq(o.script, expected[i]!.script));
}

// ---------------------------------------------------------------------------
// genesis / setup tx (tx-nft §2)
// ---------------------------------------------------------------------------

export interface GenesisConfig {
  readonly network: 'mainnet' | 'testnet' | 'regtest';
  readonly gameId: Uint8Array;          // 32-byte table id (provenance root)
  readonly seatPkhs: readonly Uint8Array[];
  readonly bankPkh: Uint8Array;
  readonly startingBalance: number;
  readonly bankReserve: number;
  readonly fundingInputs: readonly Outpoint[];
  readonly beaconSeed: Uint8Array;      // initial prev_beacon (≥32 bytes)
}

export interface GenesisResult {
  readonly tx: Tx;
  readonly titleVout: Readonly<Record<number, number>>; // property_id -> output index
  readonly reprieveVouts: readonly number[];
  readonly reserveVout: number;
  readonly paramsVout: number;
  readonly beaconVout: number;
}

const toHex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

/** A 1-sat data-carrying output: `<blob> OP_DROP <P2PKH(bank)>`. */
function dataOutput(blob: Uint8Array, bankPkh: Uint8Array): TxOutput {
  return {
    satoshis: 1,
    script: serializeScript([push(blob), op(OP.OP_DROP), op(OP.OP_DUP), op(OP.OP_HASH160), push(bankPkh), op(OP.OP_EQUALVERIFY), op(OP.OP_CHECKSIG)]),
  };
}

/** Build the genesis/setup tx. */
export function buildGenesis(cfg: GenesisConfig): GenesisResult {
  if (cfg.gameId.length !== 32) throw new Error('gameId must be 32 bytes');
  const genesis: Outpoint = { txid: toHex(cfg.gameId), vout: 0 };
  const titleTag = gameTag(cfg.gameId, 'TITLE');
  const reprieveTag = gameTag(cfg.gameId, 'REPRIEVE');

  const outputs: TxOutput[] = [];
  const titleVout: Record<number, number> = {};
  const reprieveVouts: number[] = [];

  // 1-sat title NFTs (one per titled board space), held by the bank
  for (const sp of P.board) {
    if (sp.type === 'property' || sp.type === 'station' || sp.type === 'utility') {
      const state: TitleState = {
        kind: 'TITLE', gameTag: titleTag, propertyId: sp.id, groupId: groupOrdinal(sp.group ?? ''),
        buildLevel: 0, mortgaged: false, genesis,
      };
      titleVout[sp.id] = outputs.length;
      outputs.push(nftOutput(state, cfg.bankPkh));
    }
  }
  // 2 Reprieve 1-sat NFTs to the bank
  for (let i = 0; i < P.nfts.reprieve_cards.count; i++) {
    const state: TitleState = { kind: 'REPRIEVE', gameTag: reprieveTag, propertyId: 0, groupId: 0, buildLevel: 0, mortgaged: false, genesis };
    reprieveVouts.push(outputs.length);
    outputs.push(nftOutput(state, cfg.bankPkh));
  }
  // seat starting balances (native sats)
  for (const pkh of cfg.seatPkhs) outputs.push(paymentOutput(cfg.startingBalance, pkh));
  // bank reserve
  const reserveVout = outputs.length;
  outputs.push(paymentOutput(cfg.bankReserve, cfg.bankPkh));
  // table parameters output: H(params) ‖ networkByte ‖ seatCount  (pushdata + OP_DROP)
  const netByte = { mainnet: 0, testnet: 1, regtest: 2 }[cfg.network];
  const paramsHash = new Uint8Array(createHash('sha256').update(JSON.stringify(P)).digest());
  const paramsBlob = Uint8Array.from([...paramsHash, netByte, cfg.seatPkhs.length & 0xff]);
  const paramsVout = outputs.length;
  outputs.push(dataOutput(paramsBlob, cfg.bankPkh));
  // beacon-seed output
  const beaconVout = outputs.length;
  outputs.push(dataOutput(cfg.beaconSeed, cfg.bankPkh));

  const inputs: TxInput[] = cfg.fundingInputs.map((o) => ({ outpoint: o, owner: cfg.bankPkh, sequence: 0xffffffff }));
  const tx: Tx = { version: 1, inputs, outputs, nLockTime: 0 };
  return { tx, titleVout, reprieveVouts, reserveVout, paramsVout, beaconVout };
}
