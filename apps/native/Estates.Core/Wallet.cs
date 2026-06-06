// Estates.Core/Wallet.cs — a real BSV wallet: deterministic child keys from one master,
// real base58check P2PKH addresses, and the NFTs the wallet holds. secp256k1 only.
using System.Security.Cryptography;
using System.Text;

namespace Estates.Core;

public sealed record WalletAddress(int Index, string Priv, string Pub, string Address);
public sealed record WalletNft(string Name, string Outpoint, string Kind);

public static class Wallet
{
    private const string B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// <summary>A deterministic child private key (32 bytes) from the master at `index`.</summary>
    public static byte[] ChildPriv(byte[] master, int index)
    {
        var data = new List<byte>(master);
        data.AddRange(Encoding.ASCII.GetBytes("estates-wallet-v1"));
        data.AddRange(BitConverter.GetBytes(index));
        byte[] h = SHA256.HashData(data.ToArray());
        // ensure non-zero (a 32-byte SHA256 is a valid secp256k1 scalar with overwhelming prob.)
        return h;
    }

    /// <summary>The mainnet/BSV P2PKH address (base58check, version byte 0x00) for a pubkey.</summary>
    public static string Address(byte[] pub, byte version = 0x00)
    {
        byte[] h160 = Recovery.Hash160(pub);
        var payload = new byte[21];
        payload[0] = version;
        Array.Copy(h160, 0, payload, 1, 20);
        byte[] checksum = SHA256.HashData(SHA256.HashData(payload));
        var full = new byte[25];
        Array.Copy(payload, full, 21);
        Array.Copy(checksum, 0, full, 21, 4);
        return Base58(full);
    }

    /// <summary>Derive `count` wallet addresses from the master (receive addresses).</summary>
    public static List<WalletAddress> Addresses(byte[] master, int count, byte version = 0x00)
    {
        var outp = new List<WalletAddress>();
        for (int i = 0; i < count; i++)
        {
            byte[] priv = ChildPriv(master, i);
            byte[] pub = Cipher.PublicKey(priv);
            outp.Add(new WalletAddress(i, Tx.ToHex(priv), Tx.ToHex(pub), Address(pub, version)));
        }
        return outp;
    }

    /// <summary>The address-version byte per network (BSV: mainnet 0x00, test/regtest 0x6f).</summary>
    public static byte VersionFor(string network) => network == "mainnet" ? (byte)0x00 : (byte)0x6f;

    private static string Base58(byte[] data)
    {
        // count leading zero bytes → leading '1's
        int zeros = 0; while (zeros < data.Length && data[zeros] == 0) zeros++;
        var num = new System.Numerics.BigInteger(data.Reverse().Concat(new byte[] { 0 }).ToArray()); // unsigned
        var sb = new StringBuilder();
        while (num > 0) { num = System.Numerics.BigInteger.DivRem(num, 58, out var rem); sb.Insert(0, B58[(int)rem]); }
        for (int i = 0; i < zeros; i++) sb.Insert(0, '1');
        return sb.ToString();
    }
}
