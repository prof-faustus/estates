// Estates.Core/TxProtocol.cs — the ESTATES TRANSACTION-TYPE PROTOCOL SUITE. The blockchain is the
// IP layer; each ESTATES transaction TYPE is its own protocol on top (like HTTP, SMTP, … each ride
// TCP/IP yet are distinct). EVERY type has: a unique protocol NUMBER, a self-identifying HEADER that
// can always be extracted as a layer, its own documented TEMPLATE (transaction/script shape) and its
// own smart contract. A node reads the header to know exactly what a transaction is for — payment,
// two-person chat, group chat, NFT mint/transfer, commitment, keep-alive, move, auction bid, … No
// type shares another's form; none is generic. The published standard is docs/PROTOCOLS.md.
//
// The self-identifying header (6 bytes) is the FIRST pushdata of a type's marker output:
//   magic(3) = "EST"  ‖  type(2, little-endian protocol number)  ‖  version(1)
// so any peer extracts the protocol number exactly as one reads the TCP/UDP protocol field over IP.

namespace Estates.Core;

/// <summary>Every ESTATES transaction-type protocol number (durable, published, never reused). Like
/// IANA protocol/port numbers: the value identifies the type for all time.</summary>
public enum TxType : ushort
{
    Payment       = 1,   // a plain value transfer (P2PKH) — the base template
    Chat2P        = 2,   // two-person encrypted chat (static ECDH + AES)
    ChatGroup     = 3,   // group chat (broadcast key-graph)
    NftMint       = 4,   // mint a true encrypted NFT (card/deed) to an owner
    NftTransfer   = 5,   // transfer an NFT: spend old outpoint, re-seal to the new owner
    Commitment    = 6,   // a commit (e.g. mental-poker shuffle / dice beacon commit)
    Reveal        = 7,   // a reveal opening a prior commitment
    KeepAlive     = 8,   // a presence heartbeat — itself a transaction
    Move          = 9,   // a game move
    AuctionBid    = 10,  // a conditional auction bid (covenant)
    RoleGrant     = 11,  // award of an auctioned role (banker, dealer, …)
    Deal          = 12,  // an on-chain card deal
    Trade         = 13,  // a peer-to-peer NFT/asset trade (atomic swap)
    TableOpen     = 14,  // open a table
    GameStart     = 15,  // start a game
    Identity      = 16,  // a player IDENTITY NFT card (expandable attributes; links games + history)
    BotFundOffer  = 17,  // human → bot: the 2-of-2 funding details (txid/vout/value + pubs + refund addr)
    BotRefund     = 18,  // bot → human (on close): the half-signed 2-of-2 reclaim refunding the human 100%
}

public static class TxProtocol
{
    /// <summary>Protocol magic — marks a pushdata as an ESTATES typed-transaction header.</summary>
    public static readonly byte[] Magic = "EST"u8.ToArray();
    public const byte Version = 1;
    public const int HeaderLen = 6;   // magic(3) + type(2) + version(1)

    /// <summary>The 6-byte self-identifying header for a type (the extractable protocol layer).</summary>
    public static byte[] Header(TxType type, byte version = Version)
    {
        var h = new byte[HeaderLen];
        Array.Copy(Magic, h, 3);
        h[3] = (byte)((ushort)type & 0xff);
        h[4] = (byte)(((ushort)type >> 8) & 0xff);
        h[5] = version;
        return h;
    }

    /// <summary>Prepend the typed header to a type's payload (header ‖ payload) for the marker output.</summary>
    public static byte[] Stamp(TxType type, byte[] payload)
    {
        var o = new byte[HeaderLen + payload.Length];
        Array.Copy(Header(type), o, HeaderLen);
        Array.Copy(payload, 0, o, HeaderLen, payload.Length);
        return o;
    }

    /// <summary>TOTAL: read the protocol layer off a marker pushdata. Returns null if it is not an
    /// ESTATES typed transaction (bad magic / too short) — so a peer can always ask "what is this?".</summary>
    public static (TxType type, byte version, byte[] payload)? Read(byte[] data)
    {
        if (data is null || data.Length < HeaderLen) return null;
        if (!data.AsSpan(0, 3).SequenceEqual(Magic)) return null;
        var type = (TxType)(ushort)(data[3] | (data[4] << 8));
        return (type, data[5], data[HeaderLen..]);
    }

    /// <summary>True iff `type` is a defined protocol number in this suite.</summary>
    public static bool IsKnown(TxType type) => Enum.IsDefined(type);

    /// <summary>A published descriptor of a type (number + name + purpose) — the source the standard
    /// document (docs/PROTOCOLS.md) is generated from; every type MUST have one.</summary>
    public sealed record Descriptor(TxType Type, ushort Number, string Name, string Purpose);

    public static readonly IReadOnlyList<Descriptor> Suite = new[]
    {
        new Descriptor(TxType.Payment,     1,  "PAYMENT",      "Plain value transfer (P2PKH) — the base template."),
        new Descriptor(TxType.Chat2P,      2,  "CHAT-2P",      "Two-person encrypted chat (static ECDH + AES key)."),
        new Descriptor(TxType.ChatGroup,   3,  "CHAT-GROUP",   "Group chat under the broadcast key-graph."),
        new Descriptor(TxType.NftMint,     4,  "NFT-MINT",     "Mint a true encrypted NFT (card/deed) to an owner."),
        new Descriptor(TxType.NftTransfer, 5,  "NFT-TRANSFER", "Transfer an NFT: spend old outpoint, re-seal to new owner."),
        new Descriptor(TxType.Commitment,  6,  "COMMITMENT",   "Commit (mental-poker shuffle / dice beacon)."),
        new Descriptor(TxType.Reveal,      7,  "REVEAL",       "Reveal opening a prior commitment."),
        new Descriptor(TxType.KeepAlive,   8,  "KEEPALIVE",    "Presence heartbeat — itself a transaction."),
        new Descriptor(TxType.Move,        9,  "MOVE",         "A game move."),
        new Descriptor(TxType.AuctionBid,  10, "AUCTION-BID",  "Conditional auction bid (covenant)."),
        new Descriptor(TxType.RoleGrant,   11, "ROLE-GRANT",   "Award of an auctioned role (banker, dealer, …)."),
        new Descriptor(TxType.Deal,        12, "DEAL",         "An on-chain card deal."),
        new Descriptor(TxType.Trade,       13, "TRADE",        "Peer-to-peer NFT/asset trade (atomic swap)."),
        new Descriptor(TxType.TableOpen,   14, "TABLE-OPEN",   "Open a table."),
        new Descriptor(TxType.GameStart,   15, "GAME-START",   "Start a game."),
        new Descriptor(TxType.Identity,    16, "IDENTITY",     "A player identity NFT card — expandable attributes; links games + history."),
    };
}
