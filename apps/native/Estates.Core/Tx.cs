// Estates.Core/Tx.cs — native BSV transaction serialization + txid.
// Canonical layout: version(4 LE) ‖ varint(nIn) ‖ inputs ‖
// varint(nOut) ‖ outputs ‖ lockTime(4 LE). input = reverse(prevTxid)(32) ‖
// vout(4 LE) ‖ varint(scriptLen) ‖ script ‖ sequence(4 LE). output = value(8 LE) ‖
// varint(scriptLen) ‖ script. txid = reverse(sha256(sha256(serialized))). This is
// the foundation for porting cardnft / wallet / SPV to the native exe.
using System.Globalization;
using System.Security.Cryptography;

namespace Estates.Core;

public sealed record TxInputN(string PrevTxid, long PrevVout, byte[] ScriptSig, long Sequence);
public sealed record TxOutputN(long Value, byte[] Script);
public sealed record NativeTx(int Version, IReadOnlyList<TxInputN> Inputs, IReadOnlyList<TxOutputN> Outputs, long LockTime);

public static class Tx
{
    public static byte[] FromHex(string h)
    {
        var b = new byte[h.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = byte.Parse(h.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        return b;
    }
    public static string ToHex(ReadOnlySpan<byte> b)
    {
        var sb = new System.Text.StringBuilder(b.Length * 2);
        foreach (var x in b) sb.Append(x.ToString("x2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    private static void U32Le(List<byte> o, long n) { o.Add((byte)(n & 0xff)); o.Add((byte)((n >> 8) & 0xff)); o.Add((byte)((n >> 16) & 0xff)); o.Add((byte)((n >> 24) & 0xff)); }
    private static void U64Le(List<byte> o, long n) { for (int i = 0; i < 8; i++) o.Add((byte)((n >> (8 * i)) & 0xff)); }
    private static void Varint(List<byte> o, long n)
    {
        if (n < 0) throw new ArgumentException("varint must be non-negative");
        if (n < 0xfd) o.Add((byte)n);
        else if (n <= 0xffff) { o.Add(0xfd); o.Add((byte)(n & 0xff)); o.Add((byte)((n >> 8) & 0xff)); }
        else if (n <= 0xffffffff) { o.Add(0xfe); U32Le(o, n); }
        else { o.Add(0xff); U64Le(o, n); }
    }

    public static byte[] Hash256(byte[] b)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(sha.ComputeHash(b));
    }

    public static byte[] Serialize(NativeTx tx)
    {
        var o = new List<byte>(256);
        U32Le(o, tx.Version);
        Varint(o, tx.Inputs.Count);
        foreach (var i in tx.Inputs)
        {
            var prev = FromHex(i.PrevTxid);
            if (prev.Length != 32) throw new ArgumentException("prevTxid must be 32 bytes");
            Array.Reverse(prev);                    // display -> internal byte order
            o.AddRange(prev);
            U32Le(o, i.PrevVout);
            Varint(o, i.ScriptSig.Length); o.AddRange(i.ScriptSig);
            U32Le(o, i.Sequence);
        }
        Varint(o, tx.Outputs.Count);
        foreach (var ot in tx.Outputs)
        {
            U64Le(o, ot.Value);
            Varint(o, ot.Script.Length); o.AddRange(ot.Script);
        }
        U32Le(o, tx.LockTime);
        return o.ToArray();
    }

    /// <summary>The real txid (display byte order) = reverse(hash256(serialized)).</summary>
    public static string Txid(NativeTx tx)
    {
        var h = Hash256(Serialize(tx));
        Array.Reverse(h);
        return ToHex(h);
    }
}
