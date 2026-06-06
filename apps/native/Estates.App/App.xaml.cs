using System.Windows;

namespace Estates.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Mission-critical: a UI exception must never silently kill the app — surface
        // it and keep the window alive where possible.
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show($"ESTATES hit an error:\n\n{args.Exception.Message}", "ESTATES", MessageBoxButton.OK, MessageBoxImage.Warning);
            args.Handled = true;
        };
        // GUARANTEED TERMINATION (absolute rule): a game/lobby exists only while a player
        // is up. ShutdownMode=OnLastWindowClose means closing the window shuts the app;
        // every P2P thread is a BACKGROUND thread and every socket is owned by this one
        // process, so process exit reaps ALL of them. There is no child process and no
        // keep-alive. On Windows session end (logoff/shutdown) we also exit.
        ShutdownMode = ShutdownMode.OnLastWindowClose;
        SessionEnding += (_, _) => HardExit();
        Exit += (_, _) => HardExit();
        base.OnStartup(e);
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
}
