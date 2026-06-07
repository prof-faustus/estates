// Estates.Core/NodeService.cs — the in-client NODE: it ties the peer layer, the block pipeline
// (ChainSync), the UTXO ledger, the mempool and the wallet into ONE running unit. Blocks received from
// peers are validated (real PoW + tip linkage) into the UTXO ledger; the wallet reads its balance
// straight from that validated ledger — so a coin is credited ONLY because a validated block carried
// it (proof-gated by construction). This is "the client IS the node": no external node, no RPC.
using System.Threading.Tasks;

namespace Estates.Core;

public sealed class NodeService
{
    public UtxoSet Utxo { get; } = new();
    public Mempool Mempool { get; } = new();
    public ChainSync Chain { get; }
    public WalletEngine Wallet { get; }
    private BsvPeer? _peer;

    public NodeService(byte[] seed32, int watchHorizon = 200)
    {
        Chain = new ChainSync(Utxo, Mempool);
        Wallet = new WalletEngine(seed32, watchHorizon);
    }

    /// <summary>Ingest a raw block (from a peer, or a test). Returns true if it extended the chain —
    /// only then are its coins credited to the ledger the wallet reads.</summary>
    public bool IngestBlock(byte[] rawBlock) => Chain.OnBlock(rawBlock);

    /// <summary>Ingest an unconfirmed transaction into the mempool (0-conf).</summary>
    public string? IngestMempoolTx(byte[] rawTx) => Mempool.Accept(rawTx);

    public long Spendable() => Wallet.Spendable(Utxo);
    public long Immature() => Wallet.Immature(Utxo);
    public int Height => Chain.Height;
    public BsvPeer? Peer => _peer;

    /// <summary>Connect to a BSV peer and stream its blocks into the chain pipeline — the client
    /// running as a node. Each block is validated by ChainSync before it can affect balance.</summary>
    public async Task ConnectAsync(BsvNet net, string host, int port)
    {
        var peer = new BsvPeer(net, host, port);
        peer.OnBlock += raw => Chain.OnBlock(raw);
        _peer = peer;
        await peer.ConnectAsync().ConfigureAwait(false);
    }
}
