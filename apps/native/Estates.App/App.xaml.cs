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

        // HEADLESS SELF-TEST: estates.exe --selftest runs the REAL app code 100x with NO window, NO input,
        // NO foreground — writes the result to a file and exits. The compiled EXE is tested without ever
        // touching the user's screen, mouse, or keyboard.
        if (e.Args.Any(a => a == "--selftest")) { RunSelfTest(); Shutdown(); return; }

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
        string outp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "estates_selftest.txt");
        string tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "estates_st");
        System.IO.Directory.CreateDirectory(tmp);
        string[] nets = { "mainnet", "testnet", "regtest" };
        int ok = 0, fail = 0; string firstErr = "";
        for (int i = 1; i <= 100; i++)
        {
            try
            {
                byte[] seed = RandomNumberGenerator.GetBytes(32);
                string pw = "pw" + i + "Aa!"; string net = nets[i % 3];
                string wpath = System.IO.Path.Combine(tmp, "w" + i + ".dat");

                // (1) open / close round-trip with a different key each time; wrong password must be rejected
                WalletStore.Create(wpath, seed, pw);
                var s2 = WalletStore.Open(wpath, pw);
                if (s2 is null || !s2.AsSpan().SequenceEqual(seed)) throw new System.Exception("open round-trip mismatch");
                var bad = WalletStore.Open(wpath, pw + "x");
                if (bad is not null && bad.AsSpan().SequenceEqual(seed)) throw new System.Exception("wrong password accepted");
                var s3 = WalletStore.Open(wpath, pw);   // open / close / open / close
                if (s3 is null || !s3.AsSpan().SequenceEqual(seed)) throw new System.Exception("second open mismatch");

                // (2) construct the REAL wizard GUI (builds the actual control tree; never shown, no input)
                var wiz = new WalletWizard(); _ = wiz.Title;

                // (3) the REAL registration code (same path the live wizard runs) + signature self-verify
                WalletWizard.RegisterCore(wpath, seed, pw, "player" + i, "player" + i + "@example.com", "");

                // (4) build + SIGN a real spend with this key and verify it against the FORKID sighash
                var w = new StandaloneWallet(seed, net);
                byte[] ourScript = NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(1)));
                var outs = new System.Collections.Generic.List<TxOutputN> { new TxOutputN(50_000 + i, ourScript) };
                var ins = new System.Collections.Generic.List<TxInputN> { new TxInputN(new string('b', 64), 0, System.Array.Empty<byte>(), 0xffffffff) };
                var utx = new NativeTx(2, ins, outs, 0);
                byte[] sh = Scriptvm.Sighash(utx, 0, ourScript, 100_000 + i, 0x41);
                byte[] der = EcdsaSign.SignPrehashDer(w.ChildPriv(1), sh);
                if (!EcdsaSign.VerifyDerPrehash(w.ChildPub(1), sh, der)) throw new System.Exception("spend sig verify failed");

                System.IO.File.Delete(wpath);
                ok++;
            }
            catch (System.Exception e) { fail++; if (firstErr.Length == 0) firstErr = "iter " + i + ": " + e.Message; }
        }
        try { System.IO.File.WriteAllText(outp, $"SELFTEST {ok}/100 fail={fail}" + (firstErr.Length > 0 ? " firstErr=" + firstErr : "")); } catch { }
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
