// Estates.Core/Base58.cs — Base58Check, from scratch (no library). The BSV address + seed-backup
// encoding: version ‖ payload ‖ checksum(first 4 bytes of double-SHA256), rendered in base58. Decoding
// is TOTAL — a bad character or a bad checksum returns null, never throws.
using System.Numerics;

namespace Estates.Core;

public static class Base58
{
    private const string A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static string Encode(byte[] data)
    {
        int zeros = 0; while (zeros < data.Length && data[zeros] == 0) zeros++;
        var num = new BigInteger(data, isUnsigned: true, isBigEndian: true);
        var sb = new System.Text.StringBuilder();
        while (num > 0) { num = BigInteger.DivRem(num, 58, out var rem); sb.Insert(0, A[(int)rem]); }
        for (int i = 0; i < zeros; i++) sb.Insert(0, '1');
        return sb.Length == 0 ? "1" : sb.ToString();
    }

    public static byte[]? Decode(string s)
    {
        BigInteger num = 0;
        foreach (char c in s) { int d = A.IndexOf(c); if (d < 0) return null; num = num * 58 + d; }
        var bytes = num.IsZero ? System.Array.Empty<byte>() : num.ToByteArray(isUnsigned: true, isBigEndian: true);
        int zeros = 0; foreach (char c in s) { if (c == '1') zeros++; else break; }
        var outp = new byte[zeros + bytes.Length];
        System.Array.Copy(bytes, 0, outp, zeros, bytes.Length);
        return outp;
    }

    /// <summary>Encode version ‖ payload with a 4-byte double-SHA256 checksum.</summary>
    public static string Check(byte version, byte[] payload)
    {
        var d = new byte[1 + payload.Length]; d[0] = version; System.Array.Copy(payload, 0, d, 1, payload.Length);
        var chk = Tx.Hash256(d);
        var full = new byte[d.Length + 4]; System.Array.Copy(d, full, d.Length); System.Array.Copy(chk, 0, full, d.Length, 4);
        return Encode(full);
    }

    /// <summary>TOTAL: decode + verify the checksum. null on bad char / short / bad checksum.</summary>
    public static byte[]? CheckDecode(string s, out byte version)
    {
        version = 0;
        var raw = Decode(s);
        if (raw is null || raw.Length < 5) return null;
        var body = raw[..^4]; var chk = raw[^4..];
        var h = Tx.Hash256(body);
        for (int i = 0; i < 4; i++) if (h[i] != chk[i]) return null;
        version = body[0];
        return body[1..];
    }
}

public static class Address
{
    /// <summary>P2PKH address version byte: mainnet 0x00 ('1'), testnet/regtest 0x6f ('m'/'n').</summary>
    public static byte Version(BsvNet net) => net == BsvNet.Mainnet ? (byte)0x00 : (byte)0x6f;
    public static string P2pkh(byte[] pkh20, BsvNet net) => Base58.Check(Version(net), pkh20);
}
