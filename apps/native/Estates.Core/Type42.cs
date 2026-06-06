// Estates.Core/Type42.cs — Type-42 key derivation (the patented BSV key system), now on
// the IN-TREE secp256k1 (no third-party library). The ROOT key is NEVER shared; every key
// use / signed message derives a UNIQUE sub-key from a unique invoice number. NO BIP32, NO
// "Bitcoin seed", NO mnemonic, NO library — this is BSV.
//
//   shared = ECDH(rootPriv, counterpartyPub)           (compressed shared point)
//   k      = HMAC-SHA256(key = shared, msg = invoice) mod n
//   childPriv = (rootPriv + k) mod n      childPub = rootPub + k·G
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Estates.Core;

public static class Type42
{
    private static BigInteger K(byte[] shared, string invoice)
    {
        using var h = new HMACSHA256(shared);
        return new BigInteger(h.ComputeHash(Encoding.UTF8.GetBytes(invoice)), isUnsigned: true, isBigEndian: true) % Secp256k1.NOrder;
    }

    /// <summary>The compressed public key for a private key.</summary>
    public static byte[] PublicKey(byte[] priv) => Secp256k1.PublicKey(priv);

    /// <summary>Child PRIVATE key: (rootPriv + k) mod n, k binding ECDH(rootPriv, counterpartyPub)
    /// to `invoice`. The root is never exposed; a different invoice ⇒ a different unique key.</summary>
    public static byte[] DerivePrivate(byte[] rootPriv, byte[] counterpartyPub, string invoice)
        => Secp256k1.To32(Secp256k1.ScalarAddModN(rootPriv, K(Secp256k1.EcdhCompressed(rootPriv, counterpartyPub), invoice)));

    /// <summary>The matching child PUBLIC key: rootPub + k·G (counterparty side).</summary>
    public static byte[] DerivePublic(byte[] rootPub, byte[] counterpartyPriv, string invoice)
        => Secp256k1.Compress(Secp256k1.Add(Secp256k1.Decompress(rootPub),
               Secp256k1.Mul(K(Secp256k1.EcdhCompressed(counterpartyPriv, rootPub), invoice), Secp256k1.G)));

    /// <summary>A wallet's own UNIQUE sub-key at `index` (counterparty = the wallet's own key,
    /// so only the root holder can derive it; root never shared).</summary>
    public static byte[] WalletChildPrivate(byte[] rootPriv, int index)
        => DerivePrivate(rootPriv, PublicKey(rootPriv), $"estates-wallet-{index}");

    /// <summary>A UNIQUE sub-key bound to an arbitrary invoice — for one key per use / per
    /// signed message (the no-reuse rule). Root never shared.</summary>
    public static byte[] UniqueKey(byte[] rootPriv, string invoice)
        => DerivePrivate(rootPriv, PublicKey(rootPriv), invoice);
}
