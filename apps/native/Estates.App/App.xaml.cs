using System.Linq;
using System.Security.Cryptography;
using System.Windows;
using Estates.Core;

namespace Estates.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Mission-critical: a UI exception must never silently kill the app — surface
        // it and keep the window alive where possible.
        // Never crash silently and never pop a window: log every fault (UI thread, background threads,
        // and tasks) to a file and keep the app alive where possible.
        DispatcherUnhandledException += (_, args) => { CrashLog("UI", args.Exception); args.Handled = true; };
        AppDomain.CurrentDomain.UnhandledException += (_, e) => CrashLog("DOMAIN", e.ExceptionObject as Exception);
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) => { CrashLog("TASK", e.Exception); e.SetObserved(); };
        // GUARANTEED TERMINATION (absolute rule): a game/lobby exists only while a player
        // is up. ShutdownMode=OnLastWindowClose means closing the window shuts the app;
        // every P2P thread is a BACKGROUND thread and every socket is owned by this one
        // process, so process exit reaps ALL of them. There is no child process and no
        // keep-alive. On Windows session end (logoff/shutdown) we also exit.
        ShutdownMode = ShutdownMode.OnLastWindowClose;
        SessionEnding += (_, _) => HardExit();
        Exit += (_, _) => HardExit();
        base.OnStartup(e);

        // EVERY wallet write fans out READ-ONLY, never-deleted backups to claude\backups (and a folder beside
        // the wallet). 1 TB of tiny immutable backups is better than ever losing one seed.
        try { WalletStore.ExtraBackupDirs.Add(@"D:\claude\backups"); } catch { }

        // HEADLESS SELF-TEST: estates.exe --selftest runs the REAL app code 100x with NO window, NO input,
        // NO foreground — writes the result to a file and exits. The compiled EXE is tested without ever
        // touching the user's screen, mouse, or keyboard.
        if (e.Args.Any(a => a == "--selftest")) { RunSelfTest(); Shutdown(); return; }

        // HEADLESS MENTAL-POKER HAND: estates.exe --mphand runs a FULL dealerless on-chain mental-poker hand
        // (shuffle -> issue deck as NFTs -> threshold-deal hole cards -> showdown reveal -> end-of-game reclaim)
        // with NO window, and writes a result file. Proves the game's cryptographic core works in the real exe.
        if (e.Args.Any(a => a == "--mphand")) { RunMpHand(); Shutdown(); return; }

        // HEADLESS LIVE-NETWORK P2P TEST (signoff plumbing): estates.exe --p2ptest <testnet|mainnet|regtest>
        // [--scan <address>] [--broadcast <rawhex>] — discovers REAL public BSV nodes, handshakes, syncs the
        // header chain, and (optionally) scans for a coin / broadcasts a tx. Proves the testnet/mainnet
        // signoff path against real remote nodes with NO window and NO input. Result written to a file.
        if (e.Args.Any(a => a == "--p2ptest"))
        {
            int idx = Array.IndexOf(e.Args, "--p2ptest");
            string netArg = (idx >= 0 && idx + 1 < e.Args.Length) ? e.Args[idx + 1] : "testnet";
            RunP2PTest(netArg, e.Args);
            Shutdown(); return;
        }

        // HEADLESS SIGNOFF SEND: estates.exe --signoffsend <testnet|mainnet> [--to <addr>] [--amount <sat>]
        // Opens the signoff wallet, SCANS real nodes for its coin (receive + SPV proof), then builds + signs +
        // broadcasts a spend to real nodes (send). This is the full send+receive+proof testnet/mainnet signoff.
        if (e.Args.Any(a => a == "--signoffsend"))
        {
            int idx = Array.IndexOf(e.Args, "--signoffsend");
            string netArg = (idx >= 0 && idx + 1 < e.Args.Length) ? e.Args[idx + 1] : "testnet";
            RunSignoffSend(netArg, e.Args);
            Shutdown(); return;
        }

        // HEADLESS SIGNOFF-WALLET ADDRESS EXPORT: estates.exe --signoffaddr <testnet|mainnet|regtest>
        // creates (or re-opens) a PERSISTENT signoff wallet file and prints its seed + receive addresses/pkh.
        // The operator mines a coinbase to addr #1; the SAME wallet later opens in the GUI to scan + spend.
        if (e.Args.Any(a => a == "--signoffaddr"))
        {
            int idx = Array.IndexOf(e.Args, "--signoffaddr");
            string netArg = (idx >= 0 && idx + 1 < e.Args.Length) ? e.Args[idx + 1] : "testnet";
            RunSignoffAddr(netArg);
            Shutdown(); return;
        }

        // A bot is a SEPARATE node the human started (estates.exe --bot) and FULLY controls
        // — the same lobby and the same human controls as any player, never automated. The
        // lobby spawns it ONLY when the human clicks "Run a bot".
        bool bot = e.Args.Any(a => a == "--bot");
        // Each bot has a FIXED id (--id N), is OWNED by the human who started it (--owner handle,
        // --ownerpub hex), and is cryptographically that owner's: only the owner can run/control it.
        int botId = 1; string owner = ""; string ownerPub = "";
        for (int i = 0; i < e.Args.Length - 1; i++)
        {
            if (e.Args[i] == "--id" && int.TryParse(e.Args[i + 1], out var n) && n > 0) botId = n;
            else if (e.Args[i] == "--owner") owner = e.Args[i + 1];
            else if (e.Args[i] == "--ownerpub") ownerPub = e.Args[i + 1];
        }
        Window w = bot ? new BotWindow(botId, owner, ownerPub) : new MainWindow();   // a bot is NOT a person — its own small window
        w.Show();
    }

    /// <summary>Run the real wallet lifecycle 100x, headless. NO window is shown, NO input is taken, NO
    /// foreground stolen — it constructs the REAL wizard GUI, runs the REAL registration, opens/closes the
    /// encrypted wallet with 100 different keys/passwords/networks, and builds+signs a real spend verified
    /// against the FORKID sighash. Result written to %TEMP%/estates_selftest.txt.</summary>
    private static void RunSelfTest()
    {
        // EVIDENCE dir on disk next to the EXE — every test wallet is a NEW file kept FOREVER (immutable
        // proof the test ran). NOTHING here is ever deleted, and the user's %APPDATA% wallet is NEVER touched.
        string evidence = System.IO.Path.Combine(AppContext.BaseDirectory, "test-evidence", "run-" + System.DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));
        System.IO.Directory.CreateDirectory(evidence);
        string outp = System.IO.Path.Combine(evidence, "SELFTEST-RESULT.txt");
        var manifest = new System.Text.StringBuilder();
        string[] nets = { "mainnet", "testnet", "regtest" };
        int ok = 0, fail = 0; string firstErr = "";
        for (int i = 1; i <= 100; i++)
        {
            try
            {
                byte[] seed = RandomNumberGenerator.GetBytes(32);
                string pw = "pw" + i + "Aa!"; string net = nets[i % 3];
                string wpath = System.IO.Path.Combine(evidence, $"wallet-{i:0000}.dat");   // a NEW, distinct file
                if (System.IO.File.Exists(wpath)) throw new System.Exception("evidence wallet already exists — would overwrite; refusing");

                // (1) create this NEW wallet, then open/close/open/close it; wrong password must be rejected
                WalletStore.Create(wpath, seed, pw);
                var s2 = WalletStore.Open(wpath, pw);
                if (s2 is null || !s2.AsSpan().SequenceEqual(seed)) throw new System.Exception("open round-trip mismatch");
                var bad = WalletStore.Open(wpath, pw + "x");
                if (bad is not null && bad.AsSpan().SequenceEqual(seed)) throw new System.Exception("wrong password accepted");
                var s3 = WalletStore.Open(wpath, pw);
                if (s3 is null || !s3.AsSpan().SequenceEqual(seed)) throw new System.Exception("second open mismatch");

                // (2) construct the REAL wizard GUI (builds the actual control tree; never shown, no input)
                var wiz = new WalletWizard(); _ = wiz.Title;

                // (3) the REAL registration code, writing the identity into THIS test's evidence dir only
                WalletWizard.RegisterCore(wpath, seed, pw, "player" + i, "player" + i + "@example.com", "", evidence);

                // (4) build + SIGN a real spend with this key and verify it against the FORKID sighash
                var w = new StandaloneWallet(seed, net);
                byte[] ourScript = NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(1)));
                var outs = new System.Collections.Generic.List<TxOutputN> { new TxOutputN(50_000 + i, ourScript) };
                var ins = new System.Collections.Generic.List<TxInputN> { new TxInputN(new string('b', 64), 0, System.Array.Empty<byte>(), 0xffffffff) };
                var utx = new NativeTx(2, ins, outs, 0);
                byte[] sh = Scriptvm.Sighash(utx, 0, ourScript, 100_000 + i, 0x41);
                byte[] der = EcdsaSign.SignPrehashDer(w.ChildPriv(1), sh);
                if (!EcdsaSign.VerifyDerPrehash(w.ChildPub(1), sh, der)) throw new System.Exception("spend sig verify failed");

                // NEVER delete. The wallet file STAYS as immutable evidence.
                manifest.AppendLine($"wallet-{i:0000}.dat  net={net}  addr1={w.AddressAt(1)}  bytes={new System.IO.FileInfo(wpath).Length}");
                ok++;
            }
            catch (System.Exception e) { fail++; if (firstErr.Length == 0) firstErr = "iter " + i + ": " + e.Message; manifest.AppendLine($"wallet-{i:0000}.dat  FAILED: {e.Message}"); }
        }
        try
        {
            System.IO.File.WriteAllText(outp,
                $"SELFTEST {ok}/100 fail={fail}  (each line = one NEW wallet file left as evidence; nothing deleted)\n" +
                $"evidence dir: {evidence}\n" + (firstErr.Length > 0 ? "firstErr=" + firstErr + "\n" : "") + "\n" + manifest);
        }
        catch { }
    }

    /// <summary>Run a FULL dealerless on-chain mental-poker hand headless and write the evidence: shuffle ->
    /// issue the masked deck as NFTs -> threshold-deal hole cards to 4 players -> showdown reveal (verified) ->
    /// end-of-game reclaim. Proves the game's cryptographic core works in the shipped exe, no window.</summary>
    private static void RunMpHand()
    {
        string outp = System.IO.Path.Combine(AppContext.BaseDirectory, $"mphand-{DateTime.UtcNow:yyyyMMdd-HHmmss}Z.txt");
        var sb = new System.Text.StringBuilder();
        void W(string s) { sb.AppendLine(s); try { System.IO.File.WriteAllText(outp, sb.ToString()); } catch { } }
        try
        {
            W($"ESTATES mental-poker hand — {DateTime.UtcNow:o}");
            var hand = new MentalPokerHand(52, 4);
            byte[] tablePkh = Recovery.Hash160(Secp256k1.PublicKey(MentalPokerEC.NewScalar()));
            var scripts = hand.IssueScripts(tablePkh);
            W($"shuffle + issue: {scripts.Count} masked card NFTs minted (the shared encrypted deck)");
            var dealt = new int[4];
            for (int p = 0; p < 4; p++)
            {
                var sh = hand.DealShares(p, p, 2);
                dealt[p] = hand.Deal(p, p, new[] { sh[0], sh[1] });
                W($"  player {p}: dealt card index {dealt[p]} (own mandatory scalar + 2-of-3 others)");
            }
            bool allMatch = true;
            for (int p = 0; p < 4; p++) { int r = hand.Reveal(p); if (r != dealt[p]) allMatch = false; W($"  player {p}: showdown reveal {r} {(r == dealt[p] ? "MATCHES" : "MISMATCH")}"); }
            var outs = new List<OutpointN>();
            for (int p = 0; p < 4; p++) outs.Add(new OutpointN(new string((char)('1' + p), 64), 0));
            byte[] bank = NodeWallet.P2pkhScript(tablePkh);
            bool reclaimOk = ReclaimCovenant.Verify(ReclaimCovenant.BuildReclaim(outs, bank, 999000), outs, bank, 999000).ok;
            bool distinct = dealt.Distinct().Count() == 4;
            W($"reclaim: end-of-game reclaim of {outs.Count} cards verifies = {reclaimOk}");
            bool pass = allMatch && reclaimOk && distinct && scripts.Count == 52;
            W($"RESULT: {(pass ? "PASS — full on-chain mental-poker hand works in the shipped exe" : "FAIL")}");
        }
        catch (Exception e) { W("FATAL: " + e); }
    }

    /// <summary>Headless live-network proof: discover real public BSV nodes, handshake, sync headers, and
    /// optionally scan an address / broadcast a tx — the exact testnet/mainnet SIGNOFF path, against real
    /// remote nodes, with NO window and NO input. Writes a timestamped result file next to the EXE.</summary>
    private static void RunP2PTest(string netArg, string[] args)
    {
        var net = netArg.ToLowerInvariant() switch { "mainnet" => BsvNet.Mainnet, "regtest" => BsvNet.Regtest, _ => BsvNet.Testnet };
        string outp = System.IO.Path.Combine(AppContext.BaseDirectory, $"p2ptest-{net}-{System.DateTime.UtcNow:yyyyMMdd-HHmmss}Z.txt");
        var sb = new System.Text.StringBuilder();
        void W(string s) { sb.AppendLine(s); try { System.IO.File.WriteAllText(outp, sb.ToString()); } catch { } }
        try
        {
            W($"ESTATES P2P live-node test — net={net} — {System.DateTime.UtcNow:o}");
            var nodes = BsvSeeds.Discover(net, 12);
            W($"discovered {nodes.Count} peer endpoint(s) via DNS seeds: {string.Join(", ", nodes.ConvertAll(n => n.host + ":" + n.port))}");
            if (nodes.Count == 0) { W("RESULT: NO PEERS (DNS seeds returned nothing)"); return; }

            // (1) handshake EVERY node — record user-agent + advertised chain height (≈ network tip)
            BsvPeer? best = null; int bestH = -1; int handshakes = 0;
            foreach (var (host, port) in nodes)
            {
                try
                {
                    var peer = new BsvPeer(net, host, port);
                    var diag = new System.Collections.Generic.List<string>();
                    peer.OnRecv += c => { lock (diag) diag.Add("recv:" + c); };
                    peer.OnLog += l => { lock (diag) diag.Add("log:" + l); };
                    peer.ConnectAsync(0, 6000).GetAwaiter().GetResult();
                    for (int i = 0; i < 60 && !peer.HandshakeComplete; i++) System.Threading.Thread.Sleep(100);
                    if (!peer.HandshakeComplete) { lock (diag) W($"       diag {host}: {string.Join(" | ", diag)}"); }
                    if (peer.HandshakeComplete)
                    {
                        handshakes++;
                        W($"  OK   {host}:{port}  UA={peer.PeerUserAgent}  height={peer.PeerStartHeight}");
                        if (peer.PeerStartHeight > bestH) { bestH = peer.PeerStartHeight; best?.Dispose(); best = peer; }
                        else peer.Dispose();
                    }
                    else { W($"  --   {host}:{port}  connected, no handshake"); peer.Dispose(); }
                }
                catch (System.Exception ex) { W($"  XX   {host}:{port}  {ex.Message}"); }
            }
            W($"HANDSHAKES: {handshakes}/{nodes.Count} real nodes; best advertised height={bestH}");
            if (best is null) { W("RESULT: NO HANDSHAKE on any node"); return; }

            // (2) sync the header chain from genesis on the best peer — proves SPV header acquisition
            var headers = new System.Collections.Generic.List<byte[]>();
            var gotBatch = new System.Threading.ManualResetEventSlim(false);
            best.OnHeaders += hs => { lock (headers) headers.AddRange(hs); gotBatch.Set(); };
            byte[] locator = GenesisInternal(net);
            var swatch = System.Diagnostics.Stopwatch.StartNew();
            for (int guard = 0; guard < 6000; guard++)
            {
                int before; lock (headers) before = headers.Count;
                gotBatch.Reset();
                best.RequestHeadersAsync(new[] { locator }).GetAwaiter().GetResult();
                if (!gotBatch.Wait(10000)) break;                         // timeout → stop
                int after; byte[] last; lock (headers) { after = headers.Count; last = after > 0 ? headers[^1] : locator; }
                if (after == before) break;                               // no progress → at tip
                locator = Tx.Hash256(last);                               // internal-order hash of new tip header
                if (after - before < 2000) break;                        // short batch → tip reached
                if (after % 50000 < 2000) W($"  …headers {after}");
            }
            swatch.Stop();
            W($"HEADER SYNC: {headers.Count} headers in {swatch.Elapsed.TotalSeconds:F1}s (tip≈{bestH})");

            // (3) optional: scan a real address for a confirmed coin (after funding)
            int si = Array.IndexOf(args, "--scan");
            if (si >= 0 && si + 1 < args.Length)
            {
                string addr = args[si + 1];
                var pkh = Base58.CheckDecode(addr, out _);
                var owned = pkh is { Length: 20 } ? new[] { NodeWallet.P2pkhScript(pkh) } : System.Array.Empty<byte[]>();
                var spv = new SpvWallet(owned);
                var (coins, sats, detail) = SpvFetch.ScanAndCreditAsync(new[] { addr }, net, spv, 1024, m => W("  scan: " + m)).GetAwaiter().GetResult();
                W($"SCAN {addr}: coins={coins} sats={sats} — {detail}");
            }
            // (4) optional: broadcast a signed raw tx to ≥3 real nodes
            int bi = Array.IndexOf(args, "--broadcast");
            if (bi >= 0 && bi + 1 < args.Length)
            {
                var (ok, detail) = SpvFetch.BroadcastAsync(args[bi + 1], net).GetAwaiter().GetResult();
                W($"BROADCAST: ok={ok} — {detail}");
            }
            best.Dispose();
            W("RESULT: DONE");
        }
        catch (System.Exception e) { W("FATAL: " + e); }
    }

    /// <summary>Full headless SIGNOFF: open the signoff wallet, scan real BSV nodes for the coin paying our
    /// addresses (verify SPV proof locally = the RECEIVE), then build + FORKID-sign + broadcast a spend to
    /// real nodes (= the SEND). Proves send+receive+proof on a real network. Result written to a file.</summary>
    private static void RunSignoffSend(string netArg, string[] args)
    {
        string net = netArg.ToLowerInvariant() switch { "mainnet" => "mainnet", "regtest" => "regtest", _ => "testnet" };
        var bnet = net switch { "mainnet" => BsvNet.Mainnet, "regtest" => BsvNet.Regtest, _ => BsvNet.Testnet };
        string outp = System.IO.Path.Combine(AppContext.BaseDirectory, $"signoffsend-{net}-{System.DateTime.UtcNow:yyyyMMdd-HHmmss}Z.txt");
        var sb = new System.Text.StringBuilder();
        void W(string s) { sb.AppendLine(s); try { System.IO.File.WriteAllText(outp, sb.ToString()); } catch { } }
        try
        {
            string path = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ESTATES", $"signoff-{net}.dat");
            byte[]? seed = WalletStore.Open(path, "signoff-" + net);
            if (seed is null) { W($"cannot open signoff wallet at {path}"); return; }
            var w = new StandaloneWallet(seed, net);

            // owned scripts (addr 1..50) + script->key map for signing + address list for scanning
            var owned = new System.Collections.Generic.List<byte[]>();
            var keymap = new System.Collections.Generic.Dictionary<string, (byte[] priv, byte[] pub)>();
            var addrs = new System.Collections.Generic.List<string>();
            for (int i = 1; i <= 50; i++)
            {
                var pu = w.ChildPub(i);
                var script = NodeWallet.P2pkhScript(Recovery.Hash160(pu));
                owned.Add(script); keymap[Tx.ToHex(script)] = (w.ChildPriv(i), pu); addrs.Add(w.AddressAt(i));
            }
            var spv = new SpvWallet(owned);

            // (1) RECEIVE: scan real BSV nodes for our coins; each is proof-verified locally before crediting
            W($"scanning real {net} nodes for coins paying our addresses (SPV)…");
            var (coins, sats, detail) = SpvFetch.ScanAndCreditAsync(addrs, bnet, spv, 4096, m => W("  " + m)).GetAwaiter().GetResult();
            W($"SCAN: coins={coins} credited={sats} balance={spv.Balance()} — {detail}");
            if (spv.Balance() <= 0) { W("no spendable coins found yet (coinbase may be immature or outside the scan window)"); return; }

            // (2) SEND: pay addr#2 (self — proves send+receive), change back to addr#1, broadcast to real nodes
            string toAddr = w.AddressAt(2);
            int ti = Array.IndexOf(args, "--to"); if (ti >= 0 && ti + 1 < args.Length) toAddr = args[ti + 1];
            var toPkh = Base58.CheckDecode(toAddr, out _);
            if (toPkh is null || toPkh.Length != 20) { W($"bad --to address {toAddr}"); return; }
            long fee = 1000;
            long amount = System.Math.Max(1, spv.Balance() - fee - 1);   // sweep (minus fee); override with --amount
            int ai = Array.IndexOf(args, "--amount"); if (ai >= 0 && ai + 1 < args.Length && long.TryParse(args[ai + 1], out var amt)) amount = amt;
            byte[] changeScript = NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(1)));
            var built = SpvSpend.Build(spv, keymap, NodeWallet.P2pkhScript(toPkh), amount, fee, changeScript);
            if (built is null) { W($"insufficient funds to build spend (balance {spv.Balance()}, amount {amount}, fee {fee})"); return; }
            W($"BUILT spend: txid={built.Txid} to={toAddr} amount={amount} fee={fee} change={built.Change}");
            W($"raw={Tx.ToHex(built.Raw)}");
            var (ok, bdetail) = SpvFetch.BroadcastAsync(Tx.ToHex(built.Raw), bnet).GetAwaiter().GetResult();
            W($"BROADCAST: ok={ok} — {bdetail}");
            W(ok ? "SIGNOFF SEND COMPLETE — tx is on the real network." : "broadcast failed");
        }
        catch (System.Exception e) { W("FATAL: " + e); }
    }

    /// <summary>Create or re-open a PERSISTENT signoff wallet for a network and export its seed + first
    /// receive addresses (+ pkh) to a file. The operator mines a coinbase to addr #1; the same wallet file
    /// later opens in the GUI to scan the coin and spend it — proving send+receive+SPV on a real network.</summary>
    private static void RunSignoffAddr(string netArg)
    {
        string net = netArg.ToLowerInvariant() switch { "mainnet" => "mainnet", "regtest" => "regtest", _ => "testnet" };
        string dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ESTATES");
        System.IO.Directory.CreateDirectory(dir);
        string path = System.IO.Path.Combine(dir, $"signoff-{net}.dat");
        string pw = "signoff-" + net;
        byte[] seed;
        if (WalletStore.Exists(path)) seed = WalletStore.Open(path, pw) ?? throw new InvalidOperationException("cannot open signoff wallet");
        else { seed = RandomNumberGenerator.GetBytes(32); WalletStore.Create(path, seed, pw); }
        var w = new StandaloneWallet(seed, net);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"ESTATES signoff wallet — net={net}");
        sb.AppendLine($"walletFile={path}");
        sb.AppendLine($"password={pw}");
        sb.AppendLine($"seedhex={Tx.ToHex(seed)}");
        for (int i = 1; i <= 5; i++)
            sb.AppendLine($"addr[{i}]={w.AddressAt(i)}  pkh={Tx.ToHex(Recovery.Hash160(w.ChildPub(i)))}");
        string outp = System.IO.Path.Combine(AppContext.BaseDirectory, $"signoff-{net}-address.txt");
        System.IO.File.WriteAllText(outp, sb.ToString());
    }

    /// <summary>Genesis block hash in INTERNAL byte order (getheaders locator) for each network.</summary>
    private static byte[] GenesisInternal(BsvNet net)
    {
        string disp = net switch
        {
            BsvNet.Mainnet => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            BsvNet.Testnet => "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            _ => "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        };
        var b = Tx.FromHex(disp); System.Array.Reverse(b); return b;
    }

    /// <summary>Owners of live resources (the P2P node) add a clean teardown here so a
    /// close leaves the multicast group + sockets cleanly just before the process dies.
    /// Even with NO teardown registered, HardExit still terminates the whole process.</summary>
    internal static readonly List<System.Action> Teardowns = new();

    /// <summary>Force the WHOLE process (and every thread/socket) dead — 100%, always.
    /// If a player closes and ANYTHING stays running, that is a reject; this backstop
    /// guarantees nothing can ever linger even if some thread were stuck.</summary>
    private static bool _exiting;
    internal static void HardExit()
    {
        if (_exiting) return;
        _exiting = true;
        foreach (var t in Teardowns) { try { t(); } catch { } }  // clean socket teardown
        Environment.Exit(0);                                     // OS reaps every thread + socket — nothing survives
    }

    /// <summary>Append a fault to a crash log (never throws, never opens a window).</summary>
    internal static void CrashLog(string where, System.Exception? ex)
    {
        try { System.IO.File.AppendAllText(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "estates-crash.log"), $"{System.DateTime.Now:o} [{where}] {ex}\n\n"); } catch { }
    }
}
