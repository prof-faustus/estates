// Estates.Core/MentalPokerDeck.cs — integrates the two verified layers into the user's full deal:
//   (1) the provably-random, dealerless SHUFFLE (MentalPokerEC.ShuffleMask/Remask + ShuffleProof) gives a
//       masked deck where deck[k] = (∏_p d_{p,k})·M_{σ(k)} — every position carries a hidden card under the
//       product of EVERY player's secret per-card scalar;
//   (2) the COLLUSION-PROOF THRESHOLD DEAL: to deal position k to recipient R, the OTHER players' combined
//       per-card scalar D = ∏_{p≠R} d_{p,k} is Shamir-shared (t-of-(n-1)); R reconstructs D from ANY t of
//       those shares, multiplies by R's OWN mandatory scalar d_{R,k} (never shared), strips the product from
//       the point, and identifies the card.
//
// Therefore — under the threat model (all hostile, all servers compromised, the other n-1 always collude):
//   • the other n-1 colluding CANNOT open R's card (they lack d_{R,k});
//   • R CANNOT self-deal (R needs t of the others' shares to rebuild D);
//   • ANY t of the n-1 others suffice (robust to one offline/hostile other);
//   • and because R mixed randomness into the shuffle, the colluders can't even know WHERE R's card landed.
namespace Estates.Core;

public static class MentalPokerDeck
{
    /// <summary>The OTHER players' combined per-card mask for a position = the product (mod N) of their
    /// per-card scalars. This is what gets Shamir-shared so any t of them can hand it to the recipient.</summary>
    public static byte[] CombineOthers(IEnumerable<byte[]> othersScalars)
    {
        byte[]? acc = null;
        foreach (var s in othersScalars) acc = acc is null ? s : Secp256k1.ScalarMul(acc, s);
        return acc ?? throw new ArgumentException("at least one other player is required");
    }

    /// <summary>Shamir-share the others' combined mask among the n-1 others, threshold t (so any t reconstruct
    /// it; fewer than t reveal nothing). One share goes to each other player.</summary>
    public static List<Shamir.Share> ShareOthers(byte[] othersCombined, int t, int others)
        => Shamir.Split(othersCombined, t, others);

    /// <summary>DEAL the card at position k to the recipient: reconstruct the others' combined mask from ANY t
    /// shares, combine with the recipient's OWN mandatory scalar, strip both from the deck point, and identify
    /// the card. Returns the card index, or -1 if it cannot be identified (not the recipient, or fewer than t
    /// valid shares) — i.e. the colluding others get -1.</summary>
    public static int Deal(byte[] deckPointK, byte[] recipientScalarK, IEnumerable<Shamir.Share> anyTShares, int deckSize)
    {
        try
        {
            byte[] othersCombined = Shamir.Reconstruct(System.Linq.Enumerable.ToArray(anyTShares));
            byte[] combined = Secp256k1.ScalarMul(othersCombined, recipientScalarK);   // = ∏ of ALL players' d for k
            byte[] m = Secp256k1.PointMul(deckPointK, Secp256k1.ScalarInverse(combined));
            return MentalPokerEC.Identify(m, deckSize);
        }
        catch { return -1; }
    }
}
