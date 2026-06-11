// Estates.Core/RevealProof.cs — REVEAL-WITH-PROOF (board / showdown). To SHOW a card to everyone, the holder
// reveals the per-card scalars for that position; ANYONE recomputes the card from the (fixed, on-chain-
// committed) masked deck point and checks it equals the claimed card. The holder can prove the TRUE card; they
// cannot fake a different one, because the masked point is committed and the unmask is deterministic — a wrong
// claim simply will not reproduce that point. No server; anyone verifies from the chain transcript.
namespace Estates.Core;

public static class RevealProof
{
    /// <summary>The true card at a position, recomputed from the committed masked point + ALL per-card scalars
    /// for it (every player's). Deterministic. -1 if the scalars do not reduce the point to a base card.</summary>
    public static int RevealedCard(byte[] deckPointK, IEnumerable<byte[]> allScalarsK, int deckSize)
    {
        try { return MentalPokerEC.Identify(MentalPokerEC.Unmask(deckPointK, allScalarsK), deckSize); }
        catch { return -1; }
    }

    /// <summary>Verify a CLAIM that position k holds a specific card: recompute from the committed point + the
    /// revealed scalars and require equality. A false claim is rejected — it cannot be faked.</summary>
    public static bool Verify(byte[] deckPointK, IEnumerable<byte[]> allScalarsK, int claimedCard, int deckSize)
        => claimedCard >= 0 && RevealedCard(deckPointK, allScalarsK, deckSize) == claimedCard;
}
