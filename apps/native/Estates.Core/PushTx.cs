// Estates.Core/PushTx.cs — OP_PUSH_TX, the basis of REAL on-chain smart contracts on BSV. A
// covenant forces the spending transaction to PUSH its own sighash preimage in the unlocking
// script; the locking script proves the pushed preimage is genuinely this tx's (it ties the
// preimage to the transaction the node is validating) and then INTROSPECTS the preimage's fields
// — chiefly hashOutputs — to constrain WHERE and HOW the funds may move. That constraint is
// enforced by Bitcoin Script itself (every node/miner rejects a non-conforming spend), NOT by an
// off-chain predicate — the distinction the bank-covenant audit (4.1) turned on.
//
// The genuineness proof uses BSV's restored OP_CHECKDATASIG together with OP_CHECKSIG: a single
// signature `s` is checked by OP_CHECKSIG (so `s` signs THIS tx's sighash = double-SHA256(preimage))
// AND by OP_CHECKDATASIG over SHA256(preimage) (so `s` also signs SHA256(SHA256(preimage))). One
// ECDSA signature can verify two messages under one key only if the messages are equal, so the
// pushed preimage must be the real one. With the preimage proven genuine, OP-level field extraction
// makes hashOutputs (and value/sequence/locktime) trustworthy inputs to the contract's predicate.
//
// Library-free: preimage bytes are built in-tree; hashing is Tx.Hash256; signature checks are the
// in-tree Secp256k1/EcdsaSign. This file provides the preimage + a faithful executable model of the
// covenant check (the same logic the emitted Script runs), so contracts are verifiable end to end.

namespace Estates.Core;

public static class PushTx
{
    public const long SighashAllForkId = 0x41;   // SIGHASH_ALL | SIGHASH_FORKID (BSV)

    private static void U32(List<byte> o, long n) { for (int i = 0; i < 4; i++) o.Add((byte)((n >> (8 * i)) & 0xff)); }
    private static void U64(List<byte> o, long n) { for (int i = 0; i < 8; i++) o.Add((byte)((n >> (8 * i)) & 0xff)); }
    private static void Varint(List<byte> o, long n)
    {
        if (n < 0xfd) o.Add((byte)n);
        else if (n <= 0xffff) { o.Add(0xfd); o.Add((byte)(n & 0xff)); o.Add((byte)((n >> 8) & 0xff)); }
        else if (n <= 0xffffffff) { o.Add(0xfe); U32(o, n); }
        else { o.Add(0xff); U64(o, n); }
    }
    private static byte[] Rev(string txid) { var b = Tx.FromHex(txid); Array.Reverse(b); return b; }

    /// <summary>The FORKID sighash PREIMAGE for input `i` (the bytes OP_PUSH_TX reveals).
    /// double-SHA256 of this equals Scriptvm.Sighash(...) — asserted by the conformance KAT.</summary>
    public static byte[] Preimage(NativeTx tx, int i, byte[] scriptCode, long value, long sighashType = SighashAllForkId)
    {
        var hp = new List<byte>(); foreach (var inp in tx.Inputs) { hp.AddRange(Rev(inp.PrevTxid)); U32(hp, inp.PrevVout); }
        byte[] hashPrevouts = Tx.Hash256(hp.ToArray());
        var hs = new List<byte>(); foreach (var inp in tx.Inputs) U32(hs, inp.Sequence);
        byte[] hashSequence = Tx.Hash256(hs.ToArray());
        byte[] hashOutputs = HashOutputs(tx);

        var inI = tx.Inputs[i];
        var pre = new List<byte>(256);
        U32(pre, tx.Version);
        pre.AddRange(hashPrevouts); pre.AddRange(hashSequence);
        pre.AddRange(Rev(inI.PrevTxid)); U32(pre, inI.PrevVout);
        Varint(pre, scriptCode.Length); pre.AddRange(scriptCode);
        U64(pre, value); U32(pre, inI.Sequence);
        pre.AddRange(hashOutputs); U32(pre, tx.LockTime); U32(pre, sighashType);
        return pre.ToArray();
    }

    /// <summary>double-SHA256 of every output (value ‖ scriptLen ‖ script) — the field a covenant
    /// reads to constrain the spend's outputs.</summary>
    public static byte[] HashOutputs(NativeTx tx)
    {
        var ho = new List<byte>();
        foreach (var o in tx.Outputs) { U64(ho, o.Value); Varint(ho, o.Script.Length); ho.AddRange(o.Script); }
        return Tx.Hash256(ho.ToArray());
    }

    /// <summary>The sighash (double-SHA256 of the preimage) — must equal Scriptvm.Sighash.</summary>
    public static byte[] Sighash(NativeTx tx, int i, byte[] scriptCode, long value, long sighashType = SighashAllForkId)
        => Tx.Hash256(Preimage(tx, i, scriptCode, value, sighashType));

    /// <summary>The OP_PUSH_TX genuineness check (executable model of the on-chain Script). On-chain,
    /// the locking script proves the pushed `preimage` is THIS spend's via OP_CHECKSIG + OP_CHECKDATASIG
    /// on one signature (one ECDSA sig can verify two messages under a key only if they're equal, so
    /// tx-sighash == double-SHA256(preimage) ⇒ the preimage is genuine). Here we enforce the identical
    /// guarantee by RECONSTRUCTING the canonical preimage for this input and requiring an exact match —
    /// a covenant is permissionless-if-conditions-met, so no spend signature is required. Returns the
    /// now-trustworthy hashOutputs the contract constrains, or null if the preimage is not genuine.</summary>
    public static byte[]? CheckPreimage(NativeTx tx, int i, byte[] scriptCode, long value, byte[] preimage, long sighashType = SighashAllForkId)
    {
        byte[] expect = Preimage(tx, i, scriptCode, value, sighashType);
        if (!expect.AsSpan().SequenceEqual(preimage)) return null;
        return PreimageHashOutputs(preimage, scriptCode.Length);
    }

    /// <summary>Extract the 32-byte hashOutputs field from a preimage whose scriptCode is `scriptLen`
    /// bytes long. Layout: 4 + 32 + 32 + 36 + varint(scriptLen)+scriptLen + 8 + 4 + [hashOutputs] ...</summary>
    public static byte[] PreimageHashOutputs(byte[] preimage, int scriptLen)
    {
        int off = 4 + 32 + 32 + 36;
        off += VarintLen(scriptLen) + scriptLen;   // scriptCode (varint length prefix + bytes)
        off += 8 + 4;                                // value + nSequence
        return preimage[off..(off + 32)];
    }
    private static int VarintLen(int n) => n < 0xfd ? 1 : n <= 0xffff ? 3 : 5;
}
