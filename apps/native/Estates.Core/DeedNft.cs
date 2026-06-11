// Estates.Core/DeedNft.cs — title deeds are TRUE ENCRYPTED NFTs.
//
// In Estates a property you own isn't a row in a server's database — it's an encrypted NFT carried on-chain
// and SEALED to your key. Only the owner can open (decrypt) the deed; everyone else sees opaque bytes. A
// transfer RE-SEALS the deed to the new owner, so the old owner's copy is dead and only the new owner can
// read it — digital scarcity (Alice→Bob ⇒ Bob has it, Alice does not). This wraps the audited ECDH+AES NFT
// carrier (OnChainActions) and binds it to the game's title/seat model, so the engine's ownership is backed
// by real, owner-only, on-chain encrypted assets.
using System.Security.Cryptography;

namespace Estates.Core;

/// <summary>A seat's deterministic on-chain identity key (the key its deeds are sealed to).</summary>
public sealed record SeatKey(int Seat, byte[] Priv, byte[] Pub);

/// <summary>A minted deed: the property, the seat it's sealed to, and the on-chain encrypted NFT bytes.</summary>
public sealed record DeedMint(int PropertyId, int Owner, byte[] NftData);

public static class DeedNft
{
    /// <summary>Deterministic per-seat keypairs from a root secret (in a real game each seat brings its own
    /// identity key; here we derive them reproducibly so a game's deeds are auditable end-to-end).</summary>
    public static SeatKey[] DeriveSeatKeys(byte[] root, int seats)
    {
        var ks = new SeatKey[seats];
        for (int i = 0; i < seats; i++)
        {
            byte[] priv; int n = 0;
            do { priv = SHA256.HashData(Concat(root, U32(i), U32(n++))); } while (!Secp256k1.IsValidScalar(priv));
            ks[i] = new SeatKey(i, priv, Secp256k1.PublicKey(priv));
        }
        return ks;
    }

    /// <summary>The deed "face" — what is encrypted inside the NFT (only the owner ever sees this).</summary>
    public static byte[] DeedFace(int propertyId, string name, int owner)
        => System.Text.Encoding.UTF8.GetBytes(
            $"{{\"deed\":{propertyId},\"name\":\"{Esc(name)}\",\"owner\":{owner}}}");

    /// <summary>Mint a title deed as an encrypted NFT sealed to `ownerPub`, carried on-chain by `issuer`.</summary>
    public static DeedMint Mint(StandaloneWallet issuer, int propertyId, string name, int owner, byte[] ownerPub, long fee)
    {
        var cm = OnChainActions.MintCard(issuer, DeedFace(propertyId, name, owner), ownerPub, fee);
        return new DeedMint(propertyId, owner, cm.NftData);
    }

    /// <summary>Open a deed you own — returns the decrypted face, or null for anyone who is not the sealed
    /// owner (the scarcity guarantee).</summary>
    public static byte[]? Open(byte[] ownerPriv, byte[] nftData) => OnChainActions.OpenCard(ownerPriv, nftData);

    /// <summary>Transfer a deed: re-seal the SAME property to a new owner. The returned NFT opens only for
    /// the new owner; the prior owner can no longer read it. (The real on-chain transfer also spends the old
    /// NFT outpoint — see OnChainActions.TransferCard; this is the cryptographic re-seal it performs.)</summary>
    public static DeedMint ReSeal(StandaloneWallet issuer, DeedMint deed, string name, int newOwner, byte[] newOwnerPub, long fee)
        => Mint(issuer, deed.PropertyId, name, newOwner, newOwnerPub, fee);

    private static string Esc(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
    private static byte[] U32(int n) => new[] { (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n };
    private static byte[] Concat(params byte[][] ps) { var o = new List<byte>(); foreach (var p in ps) o.AddRange(p); return o.ToArray(); }
}
