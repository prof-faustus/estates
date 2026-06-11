// Estates.Core/OnChainGame.cs — compile a whole Estates game into a chain of REAL signed BSV transactions.
//
// GamePlay gives the move stream (each with its typed on-chain payload). OnChainGame turns that stream into
// actual signed transactions: starting from one funding coin, each move becomes a 1-sat data-carrier output
// (<payload> OP_DROP P2PKH(self), no OP_RETURN) funded by the wallet, with change threaded forward so the
// moves form a real spend chain. Every tx is signed (FORKID) and locally spend-verified — so a full game is
// provably a sequence of valid BSV transactions, WITHOUT needing a node. Broadcasting them is then just I/O.
namespace Estates.Core;

public static class OnChainGame
{
    public sealed record SignedGame(
        GameResult Game,
        IReadOnlyList<StandaloneWallet.BuiltTx> Txs,
        bool AllSigned,        // every tx passes local FORKID signature verification
        bool ChainsCleanly,    // each tx spends the previous tx's change (a real linked spend chain)
        long TotalFees);

    /// <summary>Play a full game and produce a signed, self-chaining BSV transaction for every move, funded
    /// from `funding` (a P2PKH coin the wallet holds at address 0). Verifies every signature locally. Pure
    /// crypto + tx building — no node, no network.</summary>
    public static SignedGame PlayAndSign(StandaloneWallet wallet, Coin funding,
        string network, int seats, long bankReserve, byte[] seed, long feePerMove = 1)
    {
        var game = GamePlay.PlayToEnd(network, seats, bankReserve, seed);
        byte[] selfPkh = Recovery.Hash160(wallet.ChildPub(0));

        // seed the wallet with the single funding coin
        foreach (var c in wallet.Coins.ToList()) wallet.SpendCoins(new[] { c });
        wallet.AddCoin(funding.Txid, funding.Vout, funding.Sats, funding.AddrIndex);

        var txs = new List<StandaloneWallet.BuiltTx>(game.Moves.Count);
        bool chains = true;
        long fees = 0;
        string? prevTxid = null;

        foreach (var move in game.Moves)
        {
            byte[] carrier = OnChainActions.CarrierScript(move.OnChainPayload, selfPkh);
            var built = wallet.BuildAndSign(new[] { new TxOutputN(1, carrier) }, feePerMove, changeIndex: 0);
            // a real chain: from the 2nd move on, this tx must consume the previous move-tx's change output
            if (prevTxid != null && !built.Spent.Any(c => c.Txid == prevTxid)) chains = false;
            txs.Add(built);
            fees += built.Fee;

            // thread the change forward as the next spendable coin (the chain link)
            wallet.SpendCoins(built.Spent);
            if (built.Change > 0)
            {
                int changeVout = built.Tx.Outputs.Count - 1;   // change is appended last
                wallet.AddCoin(built.Txid, changeVout, built.Change, 0);
                prevTxid = built.Txid;
            }
            else { prevTxid = null; }   // ran out of change — would need a new funding coin to continue
        }

        bool allSigned = txs.All(wallet.VerifySpend);
        return new SignedGame(game, txs, allSigned, chains, fees);
    }
}
