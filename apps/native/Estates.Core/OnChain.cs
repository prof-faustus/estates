// Estates.Core/OnChain.cs — anchor a game move as a REAL on-chain BSV transaction.
//
// Every move is recorded on chain: spend one of the node wallet's UTXOs into an output
// whose live locking script carries the move bytes as pushdata consumed by OP_DROP,
// followed by the same P2PKH (so the coin is spendable and the move is permanently on
// chain — NO OP_RETURN). The node wallet signs and broadcasts. The returned txid is the
// move's on-chain anchor. Same code path for regtest/testnet/mainnet (just a different node).
using System.Text;

namespace Estates.Core;

public static class OnChain
{
    private const byte OP_DROP = 0x75;
    private const long FeeSats = 1000;

    /// <summary>Broadcast `moveData` (≤75 bytes) as a real on-chain tx via `node`; returns the txid.</summary>
    public static string AnchorMove(NodeRpc node, byte[] moveData)
    {
        if (moveData.Length >= 0x4c) throw new ArgumentException("move data must be < 76 bytes (single pushdata)");
        var utxos = node.ListUnspent();
        if (utxos.Count == 0) throw new InvalidOperationException("no funds on the node to anchor the move — fund the wallet first");

        // largest UTXO, enough to cover the fee
        var u = utxos[0];
        foreach (var c in utxos) if (c.amount > u.amount) u = c;
        long inSats = (long)(u.amount * 100_000_000m);
        long change = inSats - 1 - FeeSats;
        if (change <= 0) throw new InvalidOperationException("UTXO too small to anchor a move");

        var spk = Tx.FromHex(u.scriptPubKey);
        // output 0: a 1-sat carrier holding the move in live script (<move> OP_DROP <P2PKH>);
        // output 1: change back to a STANDARD P2PKH the node wallet still recognizes + can spend.
        var data = new List<byte> { (byte)moveData.Length };
        data.AddRange(moveData);
        data.Add(OP_DROP);
        data.AddRange(spk);

        var tx = new NativeTx(2,
            new[] { new TxInputN(u.txid, u.vout, Array.Empty<byte>(), 0xffffffff) },
            new[] { new TxOutputN(1, data.ToArray()), new TxOutputN(change, spk) }, 0);

        string signed = node.SignRaw(Tx.ToHex(Tx.Serialize(tx)));
        return node.SendRawTransaction(signed);
    }

    /// <summary>Mint a deed/card as a real 1-sat NFT to `ownerPkh`: a 1-sat output whose live
    /// script carries the deed bytes (OP_DROP) then the owner's P2PKH — so the NFT is the
    /// owner's and the deed is permanently on chain (no OP_RETURN). Change returns to source.
    /// Returns the txid of the minted NFT.</summary>
    public static string MintDeed(NodeRpc node, byte[] deedData, byte[] ownerPkh)
    {
        if (deedData.Length >= 0x4c) throw new ArgumentException("deed data must be < 76 bytes");
        var utxos = node.ListUnspent();
        if (utxos.Count == 0) throw new InvalidOperationException("no funds to mint the deed NFT");
        var u = utxos[0];
        foreach (var c in utxos) if (c.amount > u.amount) u = c;
        long inSats = (long)(u.amount * 100_000_000m);
        long change = inSats - 1 - FeeSats;
        if (change <= 0) throw new InvalidOperationException("UTXO too small to mint a deed NFT");

        var nft = new List<byte> { (byte)deedData.Length };
        nft.AddRange(deedData);
        nft.Add(OP_DROP);
        nft.AddRange(Recovery.P2pkh(ownerPkh));   // owner's spend predicate

        var tx = new NativeTx(2,
            new[] { new TxInputN(u.txid, u.vout, Array.Empty<byte>(), 0xffffffff) },
            new[] { new TxOutputN(1, nft.ToArray()), new TxOutputN(change, Tx.FromHex(u.scriptPubKey)) }, 0);
        string signed = node.SignRaw(Tx.ToHex(Tx.Serialize(tx)));
        return node.SendRawTransaction(signed);
    }

    // ---- table-setup transaction (spec §6.1): one on-chain tx opens the table ----------

    /// <summary>The genesis of a table: the txid plus the vout of each 1-sat title NFT (by
    /// property id), each seat's starting-cash output, the Reprieve NFTs, and the bank reserve.</summary>
    public sealed record TableGenesis(
        string Txid,
        IReadOnlyDictionary<int, long> TitleVouts,
        IReadOnlyList<long> SeatCashVouts,
        IReadOnlyList<long> ReprieveVouts,
        long BankReserveVout);

    /// <summary>A 1-sat NFT locking script: &lt;state&gt; OP_DROP P2PKH(owner) — state in live
    /// script, no OP_RETURN, owned by `ownerPkh`.</summary>
    private static byte[] NftScript(string state, byte[] ownerPkh)
    {
        byte[] d = Encoding.ASCII.GetBytes(state);
        if (d.Length >= 0x4c) throw new ArgumentException("nft state must be < 76 bytes");
        var s = new List<byte> { (byte)d.Length };
        s.AddRange(d);
        s.Add(OP_DROP);
        s.AddRange(Recovery.P2pkh(ownerPkh));
        return s.ToArray();
    }

    /// <summary>Broadcast the table-setup transaction: mint every board title as a 1-sat NFT to
    /// the bank, mint the 2 Reprieve NFTs, issue each seat its starting sats, fund the bank
    /// reserve, and bind the network + seat count in live script. Funded/signed by the node.
    /// Returns the genesis (txid + the outpoints play will spend). NO OP_RETURN.</summary>
    public static TableGenesis TableSetup(NodeRpc node, IReadOnlyList<byte[]> seatPubs, byte[] bankPub,
        string network, long startingBalanceSats, long bankReserveSats)
    {
        byte[] bankPkh = Recovery.Hash160(bankPub);
        var outs = new List<TxOutputN>();
        var titleVouts = new Dictionary<int, long>();

        foreach (var sp in Params.Instance.Board)
        {
            if (sp.Type is "property" or "station" or "utility")
            {
                outs.Add(new TxOutputN(1, NftScript($"T:{sp.Id}:{sp.Group}:0:0", bankPkh)));
                titleVouts[sp.Id] = outs.Count - 1;
            }
        }
        var reprieve = new List<long>();
        for (int i = 0; i < 2; i++) { outs.Add(new TxOutputN(1, NftScript($"R:{i}", bankPkh))); reprieve.Add(outs.Count - 1); }

        var seatVouts = new List<long>();
        foreach (var pub in seatPubs) { outs.Add(new TxOutputN(startingBalanceSats, Recovery.P2pkh(Recovery.Hash160(pub)))); seatVouts.Add(outs.Count - 1); }

        outs.Add(new TxOutputN(bankReserveSats, Recovery.P2pkh(bankPkh)));
        long reserveVout = outs.Count - 1;
        outs.Add(new TxOutputN(1, NftScript($"P:{network}:{seatPubs.Count}", bankPkh)));   // params/seat-set bound on-chain

        long totalOut = 0; foreach (var o in outs) totalOut += o.Value;
        const long fee = 2000;
        var utxos = node.ListUnspent();
        (string txid, long vout, decimal amount, string scriptPubKey)? u = null;
        foreach (var c in utxos) if ((long)(c.amount * 100_000_000m) >= totalOut + fee) { u = c; break; }
        if (u is null) throw new InvalidOperationException("no single UTXO funds the table setup — fund the wallet first");

        long change = (long)(u.Value.amount * 100_000_000m) - totalOut - fee;
        if (change > 0) outs.Add(new TxOutputN(change, Tx.FromHex(u.Value.scriptPubKey)));

        var tx = new NativeTx(2,
            new[] { new TxInputN(u.Value.txid, u.Value.vout, Array.Empty<byte>(), 0xffffffff) }, outs, 0);
        string signed = node.SignRaw(Tx.ToHex(Tx.Serialize(tx)));
        return new TableGenesis(node.SendRawTransaction(signed), titleVouts, seatVouts, reprieve, reserveVout);
    }
}
