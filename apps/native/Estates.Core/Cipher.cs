// Estates.Core/Cipher.cs — AEAD + ECIES + authenticated key-wrap, LIBRARY-FREE: secp256k1 is the
// in-tree Secp256k1; AES-256-GCM + HKDF-SHA256 are Microsoft .NET. NO third-party library. Faithful
// to overlay-broadcast crates/cipher (constants, x-coord ECDH shared secret, 44-byte key‖nonce
// expansion, AEAD layout) so it stays byte-compatible.
using System.Security.Cryptography;
using System.Text;

namespace Estates.Core;

public static class Cipher
{
    public const int KeyLen = 32;
    public const int NonceLen = 12;
    private static readonly byte[] EciesInfo = Encoding.ASCII.GetBytes("overlay-broadcast/ecies/v1");
    private static readonly byte[] KeywrapAad = Encoding.ASCII.GetBytes("overlay-broadcast/keywrap/v1");

    // ---- AES-256-GCM (ciphertext = ct ‖ tag(16)) ----
    public static byte[] Seal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
    {
        if (key.Length != KeyLen) throw new ArgumentException("AES-256 key must be 32 bytes");
        if (nonce.Length != NonceLen) throw new ArgumentException("GCM nonce must be 12 bytes");
        var ct = new byte[plaintext.Length]; var tag = new byte[16];
        using var g = new AesGcm(key, 16);
        g.Encrypt(nonce, plaintext, ct, tag, aad);
        var packed = new byte[ct.Length + 16];
        Array.Copy(ct, packed, ct.Length); Array.Copy(tag, 0, packed, ct.Length, 16);
        return packed;
    }

    public static byte[]? Open(byte[] key, byte[] nonce, byte[] ctTag, byte[] aad)
    {
        if (key.Length != KeyLen || nonce.Length != NonceLen || ctTag.Length < 16) return null;
        int n = ctTag.Length - 16;
        var ct = new byte[n]; var tag = new byte[16];
        Array.Copy(ctTag, 0, ct, 0, n); Array.Copy(ctTag, n, tag, 0, 16);
        var plain = new byte[n];
        try { using var g = new AesGcm(key, 16); g.Decrypt(nonce, ct, tag, plain, aad); return plain; }
        catch { return null; }
    }

    private static byte[] RandomNonce() => RandomNumberGenerator.GetBytes(NonceLen);

    // ---- keys / ECDH (in-tree secp256k1) ----
    public static byte[] PublicKey(byte[] priv) => Secp256k1.PublicKey(priv);

    private static (byte[] priv, byte[] pub) EphemeralKeypair()
    {
        byte[] priv = RandomNumberGenerator.GetBytes(32);
        return (priv, Secp256k1.PublicKey(priv));
    }

    private static (byte[] key, byte[] nonce) DeriveKeyNonce(byte[] sharedX)
    {
        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedX, 44, salt: Array.Empty<byte>(), info: EciesInfo);
        var key = new byte[32]; var nonce = new byte[NonceLen];
        Array.Copy(okm, 0, key, 0, 32); Array.Copy(okm, 32, nonce, 0, NonceLen);
        return (key, nonce);
    }

    // ---- ECIES (the 2-person ECDH path): shared secret = X of (eph·recipient) ----
    public sealed record EciesCiphertext(byte[] EphemeralPublicKey, byte[] Bytes);

    public static EciesCiphertext EciesEncrypt(byte[] recipientPub33, byte[] plaintext, byte[] aad)
    {
        var (ephPriv, ephPub) = EphemeralKeypair();
        var (key, nonce) = DeriveKeyNonce(Secp256k1.EcdhX(ephPriv, recipientPub33));
        byte[] bytes = Seal(key, nonce, plaintext, aad);
        Array.Clear(key); Array.Clear(ephPriv);
        return new EciesCiphertext(ephPub, bytes);
    }

    public static byte[]? EciesDecrypt(byte[] recipientPriv, EciesCiphertext ct, byte[] aad)
    {
        try
        {
            var (key, nonce) = DeriveKeyNonce(Secp256k1.EcdhX(recipientPriv, ct.EphemeralPublicKey));
            byte[]? r = Open(key, nonce, ct.Bytes, aad);
            Array.Clear(key);
            return r;
        }
        catch { return null; }
    }

    // ---- authenticated key-wrap (GB cl.1) ----
    public sealed record WrappedKey(byte[] Nonce, byte[] Bytes);
    public static WrappedKey Wrap(byte[] wrappingKey, byte[] keyToWrap)
    {
        byte[] nonce = RandomNonce();
        return new WrappedKey(nonce, Seal(wrappingKey, nonce, keyToWrap, KeywrapAad));
    }
    public static byte[]? Unwrap(byte[] wrappingKey, WrappedKey wrapped) => Open(wrappingKey, wrapped.Nonce, wrapped.Bytes, KeywrapAad);

    // ---- symmetric/asymmetric selector ----
    public abstract record SealedMessage
    {
        public sealed record Symmetric(byte[] Nonce, byte[] Bytes) : SealedMessage;
        public sealed record Asymmetric(EciesCiphertext Ct) : SealedMessage;
    }
    public static SealedMessage SealForSymmetric(byte[] key, byte[] plaintext, byte[] aad)
    {
        byte[] nonce = RandomNonce();
        return new SealedMessage.Symmetric(nonce, Seal(key, nonce, plaintext, aad));
    }
    public static SealedMessage SealForAsymmetric(byte[] recipientPub33, byte[] plaintext, byte[] aad)
        => new SealedMessage.Asymmetric(EciesEncrypt(recipientPub33, plaintext, aad));
    public static byte[]? OpenFor(byte[]? symmetricKey, byte[]? privateKey, SealedMessage sealed_, byte[] aad)
        => sealed_ switch
        {
            SealedMessage.Symmetric s => symmetricKey is null ? null : Open(symmetricKey, s.Nonce, s.Bytes, aad),
            SealedMessage.Asymmetric a => privateKey is null ? null : EciesDecrypt(privateKey, a.Ct, aad),
            _ => null,
        };
}
