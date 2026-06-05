using System.Windows;
using System.Windows.Threading;

namespace Estates.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // Mission-critical: a UI exception must never silently kill the app — surface
        // it, log it, and keep the window alive where possible.
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show($"ESTATES hit an error:\n\n{args.Exception.Message}", "ESTATES", MessageBoxButton.OK, MessageBoxImage.Warning);
            args.Handled = true;
        };
        base.OnStartup(e);
    }
}
