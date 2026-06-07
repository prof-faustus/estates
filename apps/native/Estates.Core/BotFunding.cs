// Estates.Core/BotFunding.cs — how a human funds a bot, and how the bot refunds the human on close.
//
// THE MODEL (no import-coin, ever): the human (Alice) and the bot (Bob) form a 2-of-2 output locked to
// {AlicePub, BobPub}. Alice funds it from her SPV wallet — a REAL on-chain payment to the 2-of-2 — and
// keeps control, because spending it needs BOTH signatures. The bot can never run off with the money.
//
// ON CLOSE (refund-to-funder, mandatory): the bot builds the reclaim tx that pays 100% of the 2-of-2
// back to Alice's address, signs ITS half, and hands the half-signed reclaim + its signature to Alice
// IP-to-IP. Alice adds her signature and broadcasts. The bot then exits with nothing — no sat left.
//
// This file is the math both sides share: the 2-of-2 script, the funding record, and the refund builder.
namespace Estates.Core;

/// <summary>The shared state of one human→bot 2-of-2 funding.</summary>
public sealed record BotFund(
    string Txid, int Vout, long Value,
    byte[] AlicePub, byte[] BobPub,
    byte[] AliceRefundScript)          // P2PKH the bot must refund to (Alice's address)
{
    public byte[] LockScript => Multisig.Lock2of2(AlicePub, BobPub);
}

public static class BotFunding
{
    /// <summary>The bot's side: build the reclaim tx (100% back to Alice, minus fee) and sign the bot's
    /// half. Returns the unsigned-skeleton tx, the bot's signature, and the lock script + value Alice
    /// needs to add her signature and broadcast.</summary>
    public sealed record Refund(NativeTx Tx, byte[] BotSig, byte[] LockScript, long Value, int Index);

    public static Refund BuildBotRefund(BotFund f, byte[] botPriv, long fee)
    {
        long pay = f.Value - fee; if (pay < 0) pay = 0;
        var tx = new NativeTx(2,
            new[] { new TxInputN(f.Txid, f.Vout, System.Array.Empty<byte>(), 0xffffffff) },
            new[] { new TxOutputN(pay, f.AliceRefundScript) }, 0);
        byte[] botSig = Multisig.Sign(tx, 0, f.LockScript, f.Value, botPriv);
        return new Refund(tx, botSig, f.LockScript, f.Value, 0);
    }

    /// <summary>Alice's side: add her signature to the bot's half-signed reclaim and produce the final
    /// broadcastable tx. Verifies BOTH signatures first; returns null if the bot's signature is bad.</summary>
    public static NativeTx? CompleteRefund(Refund r, byte[] alicePriv, byte[] alicePub, byte[] botPub)
    {
        byte[] aliceSig = Multisig.Sign(r.Tx, r.Index, r.LockScript, r.Value, alicePriv);
        if (!Multisig.Verify2of2(r.Tx, r.Index, r.LockScript, r.Value, aliceSig, r.BotSig, alicePub, botPub)) return null;
        byte[] unlock = Multisig.Unlock2of2(aliceSig, r.BotSig);
        var ins = new[] { new TxInputN(r.Tx.Inputs[0].PrevTxid, r.Tx.Inputs[0].PrevVout, unlock, 0xffffffff) };
        return new NativeTx(2, ins, System.Linq.Enumerable.ToArray(r.Tx.Outputs), 0);
    }

    // --- shared wire payloads (pipe-delimited hex; both human and bot parse them totally) ---

    public static byte[] EncodeOffer(BotFund f) => System.Text.Encoding.ASCII.GetBytes(
        string.Join("|", f.Txid, f.Vout, f.Value, Tx.ToHex(f.AlicePub), Tx.ToHex(f.BobPub), Tx.ToHex(f.AliceRefundScript)));

    public static BotFund? ParseOffer(byte[] data)
    {
        try
        {
            var p = System.Text.Encoding.ASCII.GetString(data).Split('|');
            if (p.Length != 6) return null;
            return new BotFund(p[0], int.Parse(p[1]), long.Parse(p[2]), Tx.FromHex(p[3]), Tx.FromHex(p[4]), Tx.FromHex(p[5]));
        }
        catch { return null; }
    }

    public static byte[] EncodeRefund(Refund r) => System.Text.Encoding.ASCII.GetBytes(
        string.Join("|", Tx.ToHex(Tx.Serialize(r.Tx)), Tx.ToHex(r.BotSig), Tx.ToHex(r.LockScript), r.Value, r.Index));

    public static Refund? ParseRefund(byte[] data)
    {
        try
        {
            var p = System.Text.Encoding.ASCII.GetString(data).Split('|');
            if (p.Length != 5) return null;
            var tx = Tx.Parse(Tx.FromHex(p[0])); if (tx is null) return null;
            return new Refund(tx, Tx.FromHex(p[1]), Tx.FromHex(p[2]), long.Parse(p[3]), int.Parse(p[4]));
        }
        catch { return null; }
    }
}
