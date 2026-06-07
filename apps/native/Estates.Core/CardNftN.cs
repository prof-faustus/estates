// Estates.Core/CardNftN.cs — native card-NFT output + transfer.
// A card is a 1-sat UTXO whose script is
//   <ESTATES_CARD_NFT_V1 ‖ tableId(32) ‖ commitment(32) ‖ cardPub(33)> OP_DROP P2PKH(owner)
// and a transfer is a tx that SPENDS Alice's outpoint and CREATES Bob's successor
// 1-sat output — so the native exe builds the identical "Alice's card is deleted"
// transaction the web does.
using System.Globalization;
using System.Text;

namespace Estates.Core;

public sealed record OutpointN(string Txid, long Vout);

public static class CardNftN
{
    private const byte OP_DUP = 0x76, OP_DROP = 0x75, OP_HASH160 = 0xa9, OP_EQUALVERIFY = 0x88, OP_CHECKSIG = 0xac;
    private const byte OP_PUSHDATA1 = 0x4c, OP_PUSHDATA2 = 0x4d, OP_PUSHDATA4 = 0x4e;
    private static readonly byte[] CardTag = Encoding.ASCII.GetBytes("ESTATES_CARD_NFT_V1");

    private static void PushBytes(List<byte> o, byte[] data)
    {
        int n = data.Length;
        if (n < OP_PUSHDATA1) o.Add((byte)n);
        else if (n <= 0xff) { o.Add(OP_PUSHDATA1); o.Add((byte)n); }
        else if (n <= 0xffff) { o.Add(OP_PUSHDATA2); o.Add((byte)(n & 0xff)); o.Add((byte)((n >> 8) & 0xff)); }
        else { o.Add(OP_PUSHDATA4); o.Add((byte)(n & 0xff)); o.Add((byte)((n >> 8) & 0xff)); o.Add((byte)((n >> 16) & 0xff)); o.Add((byte)((n >> 24) & 0xff)); }
        o.AddRange(data);
    }

    public static byte[] EncodeCardState(string tableId, string commitment, string cardPub)
    {
        var t = Tx.FromHex(tableId); var c = Tx.FromHex(commitment); var p = Tx.FromHex(cardPub);
        if (t.Length != 32 || c.Length != 32 || p.Length != 33) throw new ArgumentException("bad card state field");
        var o = new List<byte>(CardTag.Length + 97);
        o.AddRange(CardTag); o.AddRange(t); o.AddRange(c); o.AddRange(p);
        return o.ToArray();
    }

    /// <summary>The 1-sat card NFT locking script: &lt;state&gt; OP_DROP P2PKH(owner).</summary>
    public static byte[] CardNftScript(string tableId, string commitment, string cardPub, byte[] ownerPkh)
    {
        if (ownerPkh.Length != 20) throw new ArgumentException("ownerPkh must be 20 bytes");
        var o = new List<byte>(160);
        PushBytes(o, EncodeCardState(tableId, commitment, cardPub));
        o.Add(OP_DROP);
        o.Add(OP_DUP); o.Add(OP_HASH160); PushBytes(o, ownerPkh); o.Add(OP_EQUALVERIFY); o.Add(OP_CHECKSIG);
        return o.ToArray();
    }

    /// <summary>Build the transfer tx: spend Alice's card outpoint, create Bob's
    /// successor 1-sat NFT. Returns the tx + the new outpoint (txid:0).</summary>
    public static (NativeTx Tx, OutpointN NewOutpoint) BuildTransfer(OutpointN aliceOutpoint, string tableId, string commitment, string newCardPub, byte[] bobPkh)
    {
        var script = CardNftScript(tableId, commitment, newCardPub, bobPkh);
        var tx = new NativeTx(1,
            new[] { new TxInputN(aliceOutpoint.Txid, aliceOutpoint.Vout, Array.Empty<byte>(), 0xffffffff) },
            new[] { new TxOutputN(1, script) }, 0);
        return (tx, new OutpointN(Tx.Txid(tx), 0));
    }

    /// <summary>Verify a card transfer is a true move: tx spends Alice's exact
    /// outpoint AND output[vout] is a 1-sat NFT committing to the same identity
    /// locked to Bob, with a fresh key. Total: never throws.</summary>
    public static (bool Ok, string Reason) VerifyCardTransfer(NativeTx tx, OutpointN aliceOutpoint, string aliceCardPub,
        string tableId, string commitment, string newCardPub, int newVout, byte[] bobPkh)
    {
        try
        {
            if (!tx.Inputs.Any(i => i.PrevTxid == aliceOutpoint.Txid && i.PrevVout == aliceOutpoint.Vout))
                return (false, "Alice's outpoint not spent (copy, not a move)");
            if (newCardPub == aliceCardPub) return (false, "successor reuses the retired key");
            if (newVout < 0 || newVout >= tx.Outputs.Count) return (false, "no successor output");
            var o = tx.Outputs[newVout];
            if (o.Value != 1) return (false, "successor is not 1 sat");
            var want = CardNftScript(tableId, commitment, newCardPub, bobPkh);
            if (Tx.ToHex(o.Script) != Tx.ToHex(want)) return (false, "successor does not commit to the same identity locked to Bob");
            return (true, "true move: Alice's card UTXO spent; Bob's successor created");
        }
        catch (Exception ex) { return (false, "threw: " + ex.Message); }
    }
}
