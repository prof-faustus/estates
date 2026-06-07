// Estates.Core/KeyRing.cs — the wallet's KEY RING, built from scratch on the in-tree Type-42 / HMAC
// hash-chain derivation. From ONE seed it yields an effectively unlimited index (billions → trillions)
// of UNIQUE keys: a FRESH key for every receive and every single communication, NEVER reused. The one
// exception is the IDENTITY key, which is fixed and never rotates. Per-conversation message keys are
// ECDH-bound to the counterparty and advance per message (a hash chain), so the key for transaction A
// is never the key for transaction B. Fully deterministic: the same seed reproduces the entire ring,
// so the only state worth persisting is the next-index cursor.
namespace Estates.Core;

public sealed class KeyRing
{
    private readonly byte[] _seed;
    private long _nextReceive;     // cursor: the next unused receive index (index 0 is reserved for identity)

    public KeyRing(byte[] seed32, long nextReceive = 1)
    {
        if (seed32 is null || seed32.Length != 32) throw new System.ArgumentException("seed must be 32 bytes");
        _seed = (byte[])seed32.Clone();
        _nextReceive = nextReceive < 1 ? 1 : nextReceive;
    }

    /// <summary>The ONE fixed key — the player's identity. Never rotates (reserved slot).</summary>
    public byte[] IdentityPriv() => Type42.UniqueKey(_seed, "estates/identity");
    public byte[] IdentityPub() => Secp256k1.PublicKey(IdentityPriv());

    /// <summary>A deterministic key at an arbitrary index — index is a long, so the space is trillions+.
    /// Used to scan/recover the ring from the seed alone.</summary>
    public byte[] PrivAt(long index) => Type42.UniqueKey(_seed, "estates/wallet/" + index);
    public byte[] PubAt(long index) => Secp256k1.PublicKey(PrivAt(index));

    /// <summary>The next FRESH, never-before-used receive key. Advances the cursor; the same key is
    /// never returned twice.</summary>
    public (long index, byte[] priv, byte[] pub) NextReceive()
    {
        long i = _nextReceive++;
        var p = PrivAt(i);
        return (i, p, Secp256k1.PublicKey(p));
    }
    public long NextIndex => _nextReceive;

    /// <summary>A per-message key for a conversation with `counterpartyPub`: ECDH-bound (Type-42 invoice)
    /// and advanced per `seq`, so every message uses a NEW key — a hash chain, never reused. The
    /// counterparty derives the matching public via Type42.DerivePublic with the same invoice.</summary>
    public byte[] MessagePriv(byte[] counterpartyPub, string convId, long seq)
        => Type42.DerivePrivate(_seed, counterpartyPub, "estates/msg/" + convId + "/" + seq);
    public byte[] MessagePub(byte[] counterpartyPub, string convId, long seq)
        => Secp256k1.PublicKey(MessagePriv(counterpartyPub, convId, seq));
}
