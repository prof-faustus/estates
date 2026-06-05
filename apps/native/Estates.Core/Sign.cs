// Estates.Core/Sign.cs — native per-game key derivation + Ed25519, matching
// @estates/channel. The SAME wallet master + gameId yields the SAME signing key
// here as on the web (HKDF-SHA256 over a game-scoped context), so a native player's
// identity equals the web player's. Ed25519 via BouncyCastle (reference Rfc8032).
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Estates.Core;

public static class Sign
{
    /// <summary>The Ed25519 signing key derived from a wallet master. With a gameId
    /// the key is unique to that game (one-game key); without it, the legacy
    /// game-independent key. Mirrors channel.signingKeyFromMaster exactly.</summary>
    public static (byte[] Priv, byte[] Pub) SigningKeyFromMaster(byte[] masterPriv, string? gameId = null)
    {
        string ctx = gameId is null ? "estates-ed25519-sign-v1" : $"estates-ed25519-sign-v1|game:{gameId}";
        byte[] info = Encoding.UTF8.GetBytes(ctx);
        // HKDF-SHA256, empty salt, 32-byte output — the Ed25519 private seed.
        byte[] seed = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterPriv, 32, salt: Array.Empty<byte>(), info: info);
        var pub = new byte[32];
        Ed25519.GeneratePublicKey(seed, 0, pub, 0);
        return (seed, pub);
    }

    /// <summary>Ed25519 signature over `message` by the seed (32-byte private).</summary>
    public static byte[] SignData(byte[] message, byte[] seed)
    {
        var sig = new byte[64];
        Ed25519.Sign(seed, 0, message, 0, message.Length, sig, 0);
        return sig;
    }

    /// <summary>Verify an Ed25519 signature. Total: false on malformed, never throws.</summary>
    public static bool VerifyData(byte[] message, byte[] sig, byte[] pub)
    {
        try { return sig.Length == 64 && pub.Length == 32 && Ed25519.Verify(sig, 0, pub, 0, message, 0, message.Length); }
        catch { return false; }
    }
}
