// Estates.Core/ChainSync.cs — the node's block-processing pipeline. Each incoming block is validated
// (real proof-of-work AND it links to the current tip) and then applied to the UTXO ledger and the
// mempool, advancing the tip. This is what turns raw blocks received from peers into spendable balance.
// Linear extension only here (reorg handling is a later layer): a block that fails PoW or does not
// build on the current tip is rejected. TOTAL — malformed input is rejected, never throws.
namespace Estates.Core;

public sealed class ChainSync
{
    private readonly UtxoSet _utxo;
    private readonly Mempool _mempool;
    public string TipId { get; private set; } = "";
    public int Height { get; private set; } = -1;

    public ChainSync(UtxoSet utxo, Mempool mempool) { _utxo = utxo; _mempool = mempool; }

    /// <summary>Seed the starting point (e.g. a checkpoint) so the next block must build on it.</summary>
    public void SeedTip(string tipId, int height) { TipId = tipId; Height = height; }

    /// <summary>Validate and apply a raw block. Returns true iff it extended the chain.</summary>
    public bool OnBlock(byte[] rawBlock)
    {
        var blk = Block.Parse(rawBlock);
        if (blk is null) return false;
        var hdr = BsvHeaders.Parse(blk.Header80);
        if (hdr is null || !BsvHeaders.MeetsProofOfWork(hdr)) return false;     // real PoW
        var prev = (byte[])hdr.PrevHash.Clone(); System.Array.Reverse(prev);    // internal -> display order
        string prevDisplay = Tx.ToHex(prev);
        if (Height >= 0 && prevDisplay != TipId) return false;                  // must build on the tip
        int h = Height + 1;
        _utxo.ApplyBlock(h, blk);
        _mempool.OnBlock(blk);
        TipId = blk.BlockHash;
        Height = h;
        return true;
    }
}
