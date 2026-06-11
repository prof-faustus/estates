// Estates.Core/MentalPokerHand.cs — orchestrates a full DEALERLESS mental-poker hand end to end, composing the
// verified pieces: provably-random SHUFFLE -> issue the masked deck ON-CHAIN -> collusion-proof THRESHOLD DEAL
// of cards to players -> showdown REVEAL with proof -> end-of-game RECLAIM. Pure protocol/state (no I/O); the
// game (and the bot, and local play) drives it. In real distributed play each player holds only their own
// per-card scalars; this single-process orchestrator holds them all (the canonical protocol + simulation/bot).
namespace Estates.Core;

public sealed class MentalPokerHand
{
    public int DeckSize { get; }
    public int Players { get; }
    private readonly byte[][] _deck;        // masked deck after shuffle+remask: deck[k] = (∏_p d_{p,k})·M_{σ(k)}
    private readonly byte[][][] _perCard;   // _perCard[player][position] = that player's secret per-card scalar

    /// <summary>Set up the hand: every player applies a secret global scalar + permutation (provably-random
    /// shuffle), then swaps the global for independent per-card scalars (remask). Result: a fully masked deck.</summary>
    public MentalPokerHand(int deckSize, int players)
    {
        if (deckSize < 1 || players < 2) throw new ArgumentException("need deckSize>=1 and players>=2");
        DeckSize = deckSize; Players = players;
        var deck = MentalPokerEC.BaseDeck(deckSize);
        var globals = new byte[players][];
        _perCard = new byte[players][][];
        for (int p = 0; p < players; p++)
        {
            globals[p] = MentalPokerEC.NewScalar();
            int[] perm = Deck.Permutation(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), deckSize);
            deck = MentalPokerEC.ShuffleMask(deck, globals[p], perm);
        }
        for (int p = 0; p < players; p++)
        {
            _perCard[p] = MentalPokerEC.NewPerCardScalars(deckSize);
            deck = MentalPokerEC.Remask(deck, globals[p], _perCard[p]);
        }
        _deck = deck;
    }

    /// <summary>The masked deck points (the shared encrypted deck).</summary>
    public IReadOnlyList<byte[]> MaskedDeck => _deck;

    /// <summary>The 1-sat carrier scripts to MINT the shared encrypted deck on-chain (owned by the table key).</summary>
    public List<byte[]> IssueScripts(byte[] tablePkh) => OnChainDeck.DeckScripts(_deck, tablePkh);

    /// <summary>The OTHERS' combined mask for a position (product of every non-recipient's per-card scalar).</summary>
    public byte[] OthersCombined(int position, int recipient)
    {
        var others = new List<byte[]>(Players - 1);
        for (int p = 0; p < Players; p++) if (p != recipient) others.Add(_perCard[p][position]);
        return MentalPokerDeck.CombineOthers(others);
    }

    /// <summary>Shamir-share the others' combined mask for a card dealt to <paramref name="recipient"/>: threshold
    /// t of the (Players-1) others. Each share is delivered (sealed) to one other player.</summary>
    public List<Shamir.Share> DealShares(int position, int recipient, int t)
        => MentalPokerDeck.ShareOthers(OthersCombined(position, recipient), t, Players - 1);

    /// <summary>The recipient deals their card: their OWN mandatory scalar + any t of the others' shares.
    /// Returns the card index, or -1 (the colluding others / below-threshold get -1).</summary>
    public int Deal(int position, int recipient, IEnumerable<Shamir.Share> anyTShares)
        => MentalPokerDeck.Deal(_deck[position], _perCard[recipient][position], anyTShares, DeckSize);

    /// <summary>Every player's per-card scalar for a position — revealed at showdown to PROVE the card.</summary>
    public byte[][] AllScalars(int position)
    {
        var all = new byte[Players][];
        for (int p = 0; p < Players; p++) all[p] = _perCard[p][position];
        return all;
    }

    /// <summary>Showdown reveal: the true card at a position, recomputable + verifiable by anyone from the
    /// committed deck point + the revealed scalars (RevealProof). -1 if malformed.</summary>
    public int Reveal(int position) => RevealProof.RevealedCard(_deck[position], AllScalars(position), DeckSize);
}
