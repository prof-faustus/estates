using System.Windows;

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

        // A bot is a SEPARATE node the human started (estates.exe --bot) and FULLY controls
        // — the same lobby and the same human controls as any player, never automated. The
        // lobby spawns it ONLY when the human clicks "Run a bot".
        bool bot = e.Args.Any(a => a == "--bot");
        // Each bot has a FIXED id (passed as --id N) → a SEPARATE, PERSISTENT wallet per bot. Default 1.
        int botId = 1;
        for (int i = 0; i < e.Args.Length - 1; i++) if (e.Args[i] == "--id" && int.TryParse(e.Args[i + 1], out var n) && n > 0) botId = n;
        Window w = bot ? new BotWindow(botId) : new MainWindow();   // a bot is NOT a person — its own small window
        w.Show();
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
