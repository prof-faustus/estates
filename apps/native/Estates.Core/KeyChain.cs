// Estates.Core/KeyChain.cs — PLAN §2: hash-chained Type-42 key derivation (the user's patent +
// the MANDATORY hash chain). Written from scratch on the in-tree secp256k1; Microsoft BCL only
// (SHA-256, HMAC-SHA256, System.Numerics). No third-party library; BSV-native key derivation.
//
// WHAT: a verifiable, ordered HASH CHAIN of keys. The ROOT is never shared/used directly. Every
//       key use / signed message is a UNIQUE sub-key on this chain; no key is ever reused.
// HOW : per index i —
//         link[0] = SHA256("estates-keychain/v1" ‖ rootPub)                  (genesis link)
//         link[i] = SHA256(link[i-1] ‖ be32(i))                              (the hash chain)
//         k[i]    = HMAC-SHA256( key = ECDH(rootPriv, counterpartyPub), msg = link[i] ‖ be32(i) )
//         childPriv[i] = (rootPriv + k[i]) mod n     childPub[i] = rootPub + k[i]·G
//       So each key binds: an INDEX, an ECDH shared secret, an HMAC value, AND the prior link —
//       index ‖ ECDH ‖ HMAC, hash-chained. Tamper with any earlier link and every later key/derivation
//       fails to reproduce, so the whole set is provably one chain (Verify()).
// WHY : digital scarcity under nation-state attack needs every key provably linked, ordered, and
//       one-use, with no path from a sub-key (or a leaked link) back to the root or a sibling.
using System.Numerics;
using System.Security.Cryptography;

namespace Estates.Core;

public sealed record ChainedKey(int Index, byte[] Link, byte[] Priv, byte[] Pub);

public static class KeyChain
{
    private static readonly byte[] GenesisTag = "estates-keychain/v1"u8.ToArray();

    private static byte[] Be32(int i) => new[] { (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i };
    private static byte[] Cat(byte[] a, byte[] b) { var o = new byte[a.Length + b.Length]; Array.Copy(a, o, a.Length); Array.Copy(b, 0, o, a.Length, b.Length); return o; }

    /// <summary>The genesis link of a chain: SHA256("estates-keychain/v1" ‖ rootPub).</summary>
    public static byte[] GenesisLink(byte[] rootPub) => SHA256.HashData(Cat(GenesisTag, rootPub));

    private static BigInteger K(byte[] shared, byte[] link, int index)
    {
        using var h = new HMACSHA256(shared);
        return new BigInteger(h.ComputeHash(Cat(link, Be32(index))), isUnsigned: true, isBigEndian: true) % Secp256k1.NOrder;
    }

    /// <summary>Derive the chained key at `index`: hash-chains `prevLink` forward, binds an ECDH
    /// shared secret (with `counterpartyPub`) and an HMAC, and returns the unique sub-key + its link.</summary>
    public static ChainedKey Derive(byte[] rootPriv, byte[] counterpartyPub, int index, byte[] prevLink)
    {
        byte[] link = SHA256.HashData(Cat(prevLink, Be32(index)));
        var k = K(Secp256k1.EcdhCompressed(rootPriv, counterpartyPub), link, index);
        byte[] priv = Secp256k1.To32(Secp256k1.ScalarAddModN(rootPriv, k));
        return new ChainedKey(index, link, priv, Secp256k1.PublicKey(priv));
    }

    /// <summary>The matching child PUBLIC key (counterparty side): rootPub + k·G.</summary>
    public static byte[] DerivePublic(byte[] rootPub, byte[] counterpartyPriv, int index, byte[] prevLink)
    {
        byte[] link = SHA256.HashData(Cat(prevLink, Be32(index)));
        var k = K(Secp256k1.EcdhCompressed(counterpartyPriv, rootPub), link, index);
        return Secp256k1.Compress(Secp256k1.Add(Secp256k1.Decompress(rootPub), Secp256k1.Mul(k, Secp256k1.G)));
    }

    /// <summary>A wallet's own hash-chained sub-keys [0..count) — counterparty is the wallet's own
    /// key, so only the root holder derives them; root never shared.</summary>
    public static List<ChainedKey> WalletChain(byte[] rootPriv, int count)
    {
        byte[] rootPub = Secp256k1.PublicKey(rootPriv);
        var outp = new List<ChainedKey>(count);
        byte[] link = GenesisLink(rootPub);
        for (int i = 0; i < count; i++) { var ck = Derive(rootPriv, rootPub, i, link); outp.Add(ck); link = ck.Link; }
        return outp;
    }

    /// <summary>Verify a chain is intact: each link = SHA256(prevLink ‖ be32(index)), in order from
    /// the genesis link, and each key's pub matches its priv. Any break ⇒ false.</summary>
    public static bool Verify(byte[] rootPub, IReadOnlyList<ChainedKey> chain)
    {
        byte[] link = GenesisLink(rootPub);
        for (int i = 0; i < chain.Count; i++)
        {
            var ck = chain[i];
            byte[] expect = SHA256.HashData(Cat(link, Be32(ck.Index)));
            if (ck.Index != i || !expect.AsSpan().SequenceEqual(ck.Link)) return false;
            if (!Secp256k1.PublicKey(ck.Priv).AsSpan().SequenceEqual(ck.Pub)) return false;
            link = ck.Link;
        }
        return true;
    }
}
