// Estates.Core/OnChainDeck.cs — issue the mental-poker SHARED ENCRYPTED DECK on-chain. After the dealerless
// provably-random shuffle (MentalPokerEC), each masked card point (33 bytes — the encrypted card, opaque to
// everyone because the masking IS the encryption) is carried in a 1-sat NFT output as pushdata + OP_DROP
// P2PKH(table). The whole deck is public-but-opaque on chain; the THRESHOLD DEAL (who can unmask which card)
// and the showdown REVEAL happen as later typed transactions. No OP_RETURN — state rides live script.
namespace Estates.Core;

public static class OnChainDeck
{
    /// <summary>The 1-sat carrier locking scripts for the shuffled deck: one per masked card point, each owned
    /// by the table key. Minting these is the on-chain issuance of the shared encrypted deck.</summary>
    public static List<byte[]> DeckScripts(IReadOnlyList<byte[]> maskedDeck, byte[] tablePkh)
    {
        var o = new List<byte[]>(maskedDeck.Count);
        foreach (var pt in maskedDeck) o.Add(OnChainActions.CarrierScript(TxProtocol.Stamp(TxType.Deal, pt), tablePkh));
        return o;
    }

    /// <summary>Serialize a deck (N compressed 33-byte points) for passing player-to-player over the wire.</summary>
    public static byte[] SerializeDeck(IReadOnlyList<byte[]> deck)
    {
        var o = new byte[deck.Count * 33];
        for (int i = 0; i < deck.Count; i++) Array.Copy(deck[i], 0, o, i * 33, 33);
        return o;
    }

    /// <summary>Parse a wire deck back into points, validating EVERY point is on-curve (fail-closed). null if
    /// malformed or any point is invalid — a hostile peer cannot pass a deck with a junk/off-curve card.</summary>
    public static byte[][]? DeserializeDeck(byte[] bytes)
    {
        if (bytes is null || bytes.Length == 0 || bytes.Length % 33 != 0) return null;
        int n = bytes.Length / 33;
        var d = new byte[n][];
        for (int i = 0; i < n; i++) { d[i] = bytes[(i * 33)..((i + 1) * 33)]; if (!Secp256k1.IsValidPoint(d[i])) return null; }
        return d;
    }

    /// <summary>Serialize a threshold SHARE for delivery: X(4, big-endian) ‖ Y. The share is then SEALED to the
    /// recipient (TxMessage.SealCarrier) and carried on-chain so only the recipient can read it.</summary>
    public static byte[] ShareBytes(Shamir.Share s)
    {
        var o = new byte[4 + s.Y.Length];
        o[0] = (byte)(s.X >> 24); o[1] = (byte)(s.X >> 16); o[2] = (byte)(s.X >> 8); o[3] = (byte)s.X;
        Array.Copy(s.Y, 0, o, 4, s.Y.Length);
        return o;
    }

    /// <summary>Parse a delivered share back into a Shamir.Share. null if malformed (fail-closed).</summary>
    public static Shamir.Share? ParseShare(byte[] b)
    {
        if (b is null || b.Length < 5) return null;
        int x = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
        return new Shamir.Share(x, b[4..]);
    }

    /// <summary>Recover a masked card point from a deck carrier script (round-trips <see cref="DeckScripts"/>).
    /// null if the script is not a deck carrier. This is how any peer reads the on-chain deck.</summary>
    public static byte[]? ReadDeckPoint(byte[] script)
    {
        var car = TxTransport.ReadCarrier(script);
        if (car is null) return null;
        var hdr = TxProtocol.Read(car);
        if (hdr is null || hdr.Value.type != TxType.Deal) return null;
        // defense-in-depth: a deck card MUST be a valid on-curve point — reject a hostile NFT carrying garbage
        if (!Secp256k1.IsValidPoint(hdr.Value.payload)) return null;
        return hdr.Value.payload;
    }
}
