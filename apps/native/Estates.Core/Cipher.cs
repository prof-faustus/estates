// Estates.Core/Cipher.cs — AEAD + ECDH-key encryption + authenticated key-wrap, LIBRARY-FREE:
// secp256k1 is the in-tree Secp256k1; AES-256-GCM + SHA-256 are Microsoft .NET. NO third-party
// library. ENCRYPTION IS ECDH ONLY WITH AN AES KEY (no ephemeral key, no HKDF): the two parties'
// OWN secp256k1 keys do ECDH; the shared secret's x-coordinate is
// SHA-256'd to a 32-byte AES-256 key; AES-256-GCM encrypts. ECDH(myPriv,theirPub)==ECDH(theirPriv,myPub).
using System.Security.Cryptography;
using System.Text;

namespace Estates.Core;

public static class Cipher
{
    public const int KeyLen = 32;
    public const int NonceLen = 12;
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

    // ---- ECDH + AES: the ONLY asymmetric encryption (no ephemeral key, no HKDF) ----
    /// <summary>The shared AES-256 key for two parties: the secp256k1 ECDH shared-secret x-coordinate
    /// used DIRECTLY as the 32-byte AES-256 key. Static 2-person ECDH on the parties' OWN keys, so
    /// ECDH(myPriv, theirPub) and ECDH(theirPriv, myPub) yield the identical key.</summary>
    public static byte[] EcdhKey(byte[] myPriv, byte[] theirPub) => Secp256k1.EcdhX(myPriv, theirPub);

    public sealed record EcdhSealed(byte[] Nonce, byte[] Bytes);

    /// <summary>Encrypt to `theirPub` with YOUR key `myPriv`: the ECDH x-coordinate is the AES-256 key;
    /// AES-256-GCM with a random nonce. No ephemeral key.</summary>
    public static EcdhSealed EcdhSeal(byte[] myPriv, byte[] theirPub, byte[] plaintext, byte[] aad)
    {
        byte[] key = EcdhKey(myPriv, theirPub);
        byte[] nonce = RandomNonce();
        byte[] bytes = Seal(key, nonce, plaintext, aad);
        Array.Clear(key);
        return new EcdhSealed(nonce, bytes);
    }

    /// <summary>Decrypt with YOUR key `myPriv` data sealed by `theirPub`. null on wrong key / tamper.</summary>
    public static byte[]? EcdhOpen(byte[] myPriv, byte[] theirPub, EcdhSealed ct, byte[] aad)
    {
        try { byte[] key = EcdhKey(myPriv, theirPub); byte[]? r = Open(key, ct.Nonce, ct.Bytes, aad); Array.Clear(key); return r; }
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

    // ---- symmetric selector (the broadcast key-graph wraps content keys with these) ----
    public abstract record SealedMessage
    {
        public sealed record Symmetric(byte[] Nonce, byte[] Bytes) : SealedMessage;
    }
    public static SealedMessage SealForSymmetric(byte[] key, byte[] plaintext, byte[] aad)
    {
        byte[] nonce = RandomNonce();
        return new SealedMessage.Symmetric(nonce, Seal(key, nonce, plaintext, aad));
    }
    public static byte[]? OpenFor(byte[]? symmetricKey, byte[]? privateKey, SealedMessage sealed_, byte[] aad)
    {
        _ = privateKey;   // legacy asymmetric path removed; symmetric only
        return sealed_ is SealedMessage.Symmetric s && symmetricKey is not null ? Open(symmetricKey, s.Nonce, s.Bytes, aad) : null;
    }
}
