// Estates.Core/ReclaimCovenant.cs — END-OF-GAME RECLAIM. Each card NFT is bound to the game so that when the
// game ends EVERY card is spent back into the deck / retired — no player keeps a card they were only lent.
// Modeled the project's way (nLockTime default-branch; NO CLTV/CSV): a pre-built reclaim transaction spends
// ALL of the game's card-NFT outpoints back to the bank/deck and becomes valid only at/after the game-end
// lockTime. Broadcasting it at game end retires the cards on-chain, by rule — not by trust.
using System.Linq;

namespace Estates.Core;

public static class ReclaimCovenant
{
    /// <summary>Build the reclaim tx: spend EVERY card-NFT outpoint back to the bank/deck (1 sat each), valid
    /// only at/after the game-end <paramref name="lockTime"/>. Inputs are non-final (nSequence &lt; MAX) so the
    /// lockTime is enforced. The holders pre-sign their inputs at deal time; at game end it is broadcast.</summary>
    public static NativeTx BuildReclaim(IReadOnlyList<OutpointN> cardOutpoints, byte[] bankScript, long lockTime)
    {
        if (cardOutpoints == null || cardOutpoints.Count == 0) throw new ArgumentException("no cards to reclaim");
        var inputs = cardOutpoints.Select(op => new TxInputN(op.Txid, op.Vout, Array.Empty<byte>(), 0xfffffffe)).ToList();
        var outputs = new List<TxOutputN> { new TxOutputN(cardOutpoints.Count, bankScript) };   // all dust back to the deck/bank
        return new NativeTx(2, inputs, outputs, lockTime);
    }

    /// <summary>Verify a reclaim is well-formed: it spends EXACTLY the game's card outpoints, returns the dust to
    /// the bank/deck, and is time-locked to the game end (lockTime set and inputs non-final). Total.</summary>
    public static (bool ok, string reason) Verify(NativeTx tx, IReadOnlyList<OutpointN> cardOutpoints, byte[] bankScript, long lockTime)
    {
        try
        {
            if (tx.LockTime != lockTime) return (false, "wrong lockTime (not the game-end time)");
            if (tx.Inputs.Count != cardOutpoints.Count) return (false, "does not spend exactly the game's cards");
            // reject duplicate inputs (a hostile reclaim that double-counts one card)
            var seenIn = new HashSet<string>();
            foreach (var i in tx.Inputs) if (!seenIn.Add(i.PrevTxid + ":" + i.PrevVout)) return (false, "duplicate input (a card spent twice)");
            // reject duplicate card outpoints in the spec, then require every one is reclaimed
            var seenCard = new HashSet<string>();
            foreach (var op in cardOutpoints) if (!seenCard.Add(op.Txid + ":" + op.Vout)) return (false, "duplicate card in the reclaim set");
            foreach (var op in cardOutpoints)
                if (!tx.Inputs.Any(i => i.PrevTxid == op.Txid && i.PrevVout == op.Vout)) return (false, "a card is not reclaimed");
            if (tx.Inputs.Any(i => i.Sequence == 0xffffffff)) return (false, "an input is final — the lockTime would not be enforced");
            if (tx.Outputs.Count != 1 || Tx.ToHex(tx.Outputs[0].Script) != Tx.ToHex(bankScript)) return (false, "not returned to the bank/deck");
            if (tx.Outputs[0].Value != cardOutpoints.Count) return (false, "wrong reclaim value (must be the 1-sat-per-card dust)");
            return (true, "all cards reclaimed to the bank/deck at game end (nLockTime)");
        }
        catch (Exception e) { return (false, "threw: " + e.Message); }
    }
}
