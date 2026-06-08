// Estates.Core/Bip38.cs — BIP38 private-key decryption (no-EC-multiply), for sweeping an encrypted key.
// Decode the 6P… key, scrypt(passphrase, addresshash, 16384,8,8,64) → two halves, AES-256-ECB decrypt the
// two 16-byte blocks with derivedhalf2, XOR with derivedhalf1 → the 32-byte private key, then VERIFY by
// re-deriving the address and matching its hash (wrong passphrase → null). In-tree only.
using System.Security.Cryptography;
using System.Text;

namespace Estates.Core;

public static class Bip38
{
    /// <summary>Decrypt a BIP38 (6P…) key with `passphrase`. Returns (priv, compressed) or null on a
    /// malformed key, an unsupported EC-multiply key, or a wrong passphrase.</summary>
    public static (byte[] priv, bool compressed)? Decrypt(string key, string passphrase)
    {
        var data = Base58.Decode(key);
        if (data is null || data.Length != 43) return null;            // 39-byte payload + 4-byte checksum
        var payload = data[..39];
        var chk = Tx.Hash256(payload);
        for (int i = 0; i < 4; i++) if (chk[i] != data[39 + i]) return null;   // checksum
        if (payload[0] != 0x01 || payload[1] != 0x42) return null;     // non-EC-multiply only (0x0142)
        byte flag = payload[2]; bool compressed = (flag & 0x20) != 0;
        var addrhash = payload[3..7];
        var enc = payload[7..39];                                       // 32 bytes (two AES blocks)

        byte[] pass = Encoding.UTF8.GetBytes(passphrase.Normalize(NormalizationForm.FormC));
        byte[] derived = Scrypt.DeriveKey(pass, addrhash, 16384, 8, 8, 64);
        byte[] dh1 = derived[..32], dh2 = derived[32..];
        byte[] dec = AesEcbDecrypt(enc, dh2);
        var priv = new byte[32];
        for (int i = 0; i < 32; i++) priv[i] = (byte)(dec[i] ^ dh1[i]);

        string addr = AddressFor(priv, compressed);
        var ah = Tx.Hash256(Encoding.ASCII.GetBytes(addr));
        for (int i = 0; i < 4; i++) if (ah[i] != addrhash[i]) return null;     // wrong passphrase
        return (priv, compressed);
    }

    private static byte[] AesEcbDecrypt(byte[] ct, byte[] key)
    {
        using var aes = Aes.Create(); aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key;
        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(ct, 0, ct.Length);
    }

    // the mainnet P2PKH address for this key (compressed or uncompressed pubkey, per the BIP38 flag).
    private static string AddressFor(byte[] priv, bool compressed)
    {
        byte[] comp = Secp256k1.PublicKey(priv);
        byte[] pub;
        if (compressed) pub = comp;
        else { var pt = Secp256k1.Decompress(comp); pub = new byte[65]; pub[0] = 0x04; System.Array.Copy(Secp256k1.To32(pt.X), 0, pub, 1, 32); System.Array.Copy(Secp256k1.To32(pt.Y), 0, pub, 33, 32); }
        return Address.P2pkh(Recovery.Hash160(pub), BsvNet.Mainnet);
    }
}
