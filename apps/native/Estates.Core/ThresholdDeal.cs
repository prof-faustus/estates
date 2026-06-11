// Estates.Core/ThresholdDeal.cs — the COLLUSION-PROOF threshold deal of an encrypted card to a recipient,
// implementing the user's exact rule (2026-06-10):
//
//   A card dealt to a recipient R can be opened ONLY by "R AND any t of the other n-1 players".
//   card key = H( R's MANDATORY secret share  ||  Shamir-reconstruct( t of the (n-1) others' shares ) )
//
//   - R's secret is NEVER shared  -> the others, EVEN ALL COLLUDING, cannot form the key (missing R's part);
//   - the others' secret is Shamir-shared (t-of-(n-1)) -> R CANNOT self-deal (needs t of the others), and one
//     offline/hostile other does NOT block the deal (any t of them suffice).
//
// This is layer 2 (the per-card DEAL / access-control keying) — distinct from layer 1 (sealing the card face)
// and from the mental-poker shuffle (MentalPokerEC, which provides the dealerless provably-random ordering and
// per-card privacy). The three compose: shuffle hides WHERE the card is; this controls WHO can open it.
//
// Threat model: all players hostile, all servers compromised, the other n-1 always collude against R.
using System.Security.Cryptography;

namespace Estates.Core;

public static class ThresholdDeal
{
    private static readonly byte[] Domain = "estates/threshold-card/v1"u8.ToArray();

    /// <summary>The per-card decryption key = H(domain || recipient-mandatory-secret || others-secret). Both
    /// inputs are required, so neither the recipient alone nor the others alone can form it.</summary>
    private static byte[] CardKey(byte[] recipientSecret, byte[] othersSecret)
    {
        var buf = new byte[Domain.Length + recipientSecret.Length + othersSecret.Length];
        Buffer.BlockCopy(Domain, 0, buf, 0, Domain.Length);
        Buffer.BlockCopy(recipientSecret, 0, buf, Domain.Length, recipientSecret.Length);
        Buffer.BlockCopy(othersSecret, 0, buf, Domain.Length + recipientSecret.Length, othersSecret.Length);
        return SHA256.HashData(buf);
    }

    public sealed record Dealt(Cipher.WrappedKey Sealed, IReadOnlyList<Shamir.Share> OtherShares);

    /// <summary>SEAL a card face for delivery to a recipient: encrypt the face under the card key, and split the
    /// OTHERS' secret into <paramref name="others"/> Shamir shares with threshold <paramref name="t"/> (one share
    /// per non-recipient player). <paramref name="recipientSecret"/> stays with the recipient ONLY and is never
    /// shared. Returns the sealed face + the per-other shares to distribute to each other player.</summary>
    public static Dealt Seal(byte[] face, byte[] recipientSecret, byte[] othersSecret, int t, int others)
    {
        if (t < 1 || t > others) throw new ArgumentException("threshold t must be in 1..others");
        var shares = Shamir.Split(othersSecret, t, others);
        var sealedFace = Cipher.Wrap(CardKey(recipientSecret, othersSecret), face);   // AES-256-GCM under the card key
        return new Dealt(sealedFace, shares);
    }

    /// <summary>OPEN a dealt card: the recipient supplies their MANDATORY secret plus ANY t of the other players'
    /// shares. Returns the face, or null if the key cannot be formed (not the recipient, or fewer than t valid
    /// shares). The others — even all of them, colluding — cannot open it without the recipient's secret.</summary>
    public static byte[]? Open(Cipher.WrappedKey sealedFace, byte[] recipientSecret, IEnumerable<Shamir.Share> anyTShares)
    {
        try
        {
            byte[] othersSecret = Shamir.Reconstruct(System.Linq.Enumerable.ToArray(anyTShares));
            return Cipher.Unwrap(CardKey(recipientSecret, othersSecret), sealedFace);
        }
        catch { return null; }
    }

    /// <summary>Fresh 32-byte secret (a player's mandatory share, or the others' joint secret for a card).</summary>
    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(32);
}
