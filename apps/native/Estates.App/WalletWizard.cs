using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Estates.Core;

namespace Estates.App;

/// <summary>
/// The wallet startup WIZARD — ported from ElectrumSV's wallet/account wizard flow (wallet_wizard.py +
/// account_wizard.py): a multi-page QWizard-style window with Back / Next / Cancel, page titles, and the
/// real creation path — Splash → Choose wallet → set Password → Add account (New seed | Restore) → DISPLAY
/// seed (backup) → CONFIRM seed → open. On success exposes the 32-byte seed + password; the caller persists
/// via WalletStore. Dark themed to match the wallet.
/// </summary>
public sealed class WalletWizard : Window
{
    public byte[]? Seed { get; private set; }
    public string Password { get; private set; } = "";

    private enum Step { Splash, Choose, NewPassword, SeedShow, SeedConfirm, Restore }
    private Step _step = Step.Splash;
    private byte[] _pending = System.Array.Empty<byte>();

    private static SolidColorBrush B(string h) => new((Color)ColorConverter.ConvertFromString(h));
    private readonly TextBlock _title = new() { Foreground = B("#e6e6e6"), FontSize = 20, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 4) };
    private readonly TextBlock _subtitle = new() { Foreground = B("#9aa0a6"), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 16) };
    private readonly StackPanel _body = new();
    private readonly TextBlock _msg = new() { Foreground = B("#f7a8c4"), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0) };
    private readonly Button _back = new() { Content = "‹ Back", Width = 90, Margin = new Thickness(0, 0, 8, 0) };
    private readonly Button _next = new() { Content = "Next ›", Width = 110 };
    private readonly Button _cancel = new() { Content = "Cancel", Width = 90, Margin = new Thickness(0, 0, 8, 0) };

    private readonly PasswordBox _pw = new();
    private readonly PasswordBox _pw2 = new();
    private readonly TextBox _seedShow = new() { IsReadOnly = true };
    private readonly TextBox _seedConfirm = new();
    private readonly TextBox _restoreSeed = new();
    private readonly PasswordBox _restorePw = new();

    public WalletWizard()
    {
        Title = "ESTATES — wallet setup"; Width = 560; Height = 460;
        WindowStartupLocation = WindowStartupLocation.CenterScreen; Background = B("#1b1d1e"); ResizeMode = ResizeMode.NoResize;
        foreach (var f in new Control[] { _pw, _pw2, _seedShow, _seedConfirm, _restoreSeed, _restorePw })
        { f.Background = B("#171819"); f.Foreground = B("#e6e6e6"); f.BorderThickness = new Thickness(0); f.Padding = new Thickness(8); f.Margin = new Thickness(0, 4, 0, 8); f.FontSize = 13; }
        _seedShow.FontFamily = _seedConfirm.FontFamily = _restoreSeed.FontFamily = new FontFamily("Consolas");
        _seedShow.TextWrapping = _seedConfirm.TextWrapping = _restoreSeed.TextWrapping = TextWrapping.Wrap;
        foreach (var btn in new[] { _back, _next, _cancel }) { btn.Background = B("#2d2f34"); btn.Foreground = B("#e6e6e6"); btn.BorderBrush = B("#3a3d42"); btn.Padding = new Thickness(8, 6, 8, 6); }

        var nav = new DockPanel { Margin = new Thickness(0, 14, 0, 0) };
        var right = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
        right.Children.Add(_cancel); right.Children.Add(_back); right.Children.Add(_next);
        DockPanel.SetDock(right, Dock.Right); nav.Children.Add(right);

        var root = new DockPanel { Margin = new Thickness(22) };
        DockPanel.SetDock(_title, Dock.Top); DockPanel.SetDock(_subtitle, Dock.Top); DockPanel.SetDock(nav, Dock.Bottom); DockPanel.SetDock(_msg, Dock.Bottom);
        root.Children.Add(_title); root.Children.Add(_subtitle); root.Children.Add(nav); root.Children.Add(_msg);
        root.Children.Add(new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _body });
        Content = root;

        _cancel.Click += (_, _) => { DialogResult = false; Close(); };
        _back.Click += (_, _) => Back();
        _next.Click += (_, _) => Next();
        Render();
    }

    private TextBlock Lab(string t) => new() { Text = t, Foreground = B("#9aa0a6"), FontSize = 12 };
    private Button Big(string t) => new() { Content = t, Margin = new Thickness(0, 6, 0, 6), Padding = new Thickness(12, 10, 12, 10), Background = B("#2d2f34"), Foreground = B("#e6e6e6"), BorderBrush = B("#3a3d42"), HorizontalAlignment = HorizontalAlignment.Stretch, HorizontalContentAlignment = HorizontalAlignment.Left };

    private void Render()
    {
        _body.Children.Clear(); _msg.Text = ""; _back.IsEnabled = _step != Step.Splash;
        _next.Visibility = Visibility.Visible; _next.Content = "Next ›";
        switch (_step)
        {
            case Step.Splash:
                _title.Text = "Welcome to ESTATES"; _subtitle.Text = "An ElectrumSV-class SPV wallet. Let's set up or open your wallet.";
                _body.Children.Add(Lab("Click Next to choose or create a wallet. Your keys are encrypted with a password and stored on disk, so closing keeps your money. SPV: coins arrive with their proof, IP-to-IP."));
                break;
            case Step.Choose:
            {
                _title.Text = "Choose your wallet"; _subtitle.Text = "Create a new wallet, restore one from your seed, or open an existing wallet file.";
                _next.Visibility = Visibility.Collapsed;
                bool exists = WalletStore.Exists(WalletStore.DefaultPath());
                var create = Big("➕  Create a new wallet"); create.Click += (_, _) => { _step = Step.NewPassword; Render(); };
                var restore = Big("↩  Restore from seed"); restore.Click += (_, _) => { _step = Step.Restore; Render(); };
                var open = Big(exists ? "🔓  Open my existing wallet" : "📂  Open a wallet file…"); open.Click += (_, _) => OpenExisting(exists);
                _body.Children.Add(create); _body.Children.Add(restore); _body.Children.Add(open);
                break;
            }
            case Step.NewPassword:
                _title.Text = "Set a password"; _subtitle.Text = "Your password encrypts your private keys (AES-256-GCM). You'll need it every time you open the wallet.";
                _body.Children.Add(Lab("password")); _body.Children.Add(_pw);
                _body.Children.Add(Lab("confirm password")); _body.Children.Add(_pw2);
                break;
            case Step.SeedShow:
                _title.Text = "Back up your seed"; _subtitle.Text = "Write this seed down and keep it safe. It is the ONLY way to recover your wallet and funds. Anyone with it controls your money.";
                _pending = RandomNumberGenerator.GetBytes(32); _seedShow.Text = Tx.ToHex(_pending);
                _body.Children.Add(Lab("your recovery seed (64 hex)")); _body.Children.Add(_seedShow);
                break;
            case Step.SeedConfirm:
                _title.Text = "Confirm your seed"; _subtitle.Text = "Re-enter the seed you just wrote down, to prove you have a backup.";
                _seedConfirm.Text = ""; _body.Children.Add(Lab("re-enter your seed")); _body.Children.Add(_seedConfirm);
                _next.Content = "Create wallet";
                break;
            case Step.Restore:
                _title.Text = "Restore from seed"; _subtitle.Text = "Enter your 64-hex recovery seed and set a password for this device.";
                _body.Children.Add(Lab("recovery seed (64 hex)")); _body.Children.Add(_restoreSeed);
                _body.Children.Add(Lab("password")); _body.Children.Add(_restorePw);
                _next.Content = "Restore wallet";
                break;
        }
    }

    private void Back()
    {
        _step = _step switch
        {
            Step.Choose => Step.Splash,
            Step.NewPassword => Step.Choose,
            Step.SeedShow => Step.NewPassword,
            Step.SeedConfirm => Step.SeedShow,
            Step.Restore => Step.Choose,
            _ => Step.Splash,
        };
        Render();
    }

    private void Next()
    {
        switch (_step)
        {
            case Step.Splash: _step = Step.Choose; Render(); break;
            case Step.NewPassword:
                if (_pw.Password != _pw2.Password) { _msg.Text = "passwords do not match"; return; }
                Password = _pw.Password; _step = Step.SeedShow; Render(); break;
            case Step.SeedShow: _step = Step.SeedConfirm; Render(); break;
            case Step.SeedConfirm:
                if (_seedConfirm.Text.Trim().ToLowerInvariant() != Tx.ToHex(_pending)) { _msg.Text = "that does not match the seed — check your backup"; return; }
                Finish(_pending, Password); break;
            case Step.Restore:
            {
                string h = _restoreSeed.Text.Trim();
                if (h.Length != 64) { _msg.Text = "seed must be 64 hex characters"; return; }
                byte[] s; try { s = Tx.FromHex(h); } catch { _msg.Text = "seed is not valid hex"; return; }
                Finish(s, _restorePw.Password); break;
            }
        }
    }

    private void OpenExisting(bool exists)
    {
        string path = WalletStore.DefaultPath();
        if (!exists)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Open wallet", Filter = "wallet (*.dat)|*.dat|all files|*.*" };
            if (dlg.ShowDialog() != true) return; path = dlg.FileName;
        }
        var pwWin = new PromptPw();
        if (pwWin.ShowDialog() != true) return;
        try { var s = WalletStore.Open(path, pwWin.Value); if (s is null) { _msg.Text = "wrong password, or not a wallet file"; return; } Seed = s; Password = pwWin.Value; DialogResult = true; Close(); }
        catch (System.Exception e) { _msg.Text = e.Message; }
    }

    private void Finish(byte[] seed, string password)
    {
        try { WalletStore.Create(WalletStore.DefaultPath(), seed, password); Seed = seed; Password = password; DialogResult = true; Close(); }
        catch (System.Exception e) { _msg.Text = e.Message; }
    }

    // a tiny password prompt for opening an existing wallet
    private sealed class PromptPw : Window
    {
        public string Value = "";
        public PromptPw()
        {
            Title = "Unlock wallet"; Width = 360; Height = 150; WindowStartupLocation = WindowStartupLocation.CenterScreen; Background = B("#1b1d1e"); ResizeMode = ResizeMode.NoResize;
            var sp = new StackPanel { Margin = new Thickness(16) };
            sp.Children.Add(new TextBlock { Text = "Enter your wallet password", Foreground = B("#e6e6e6"), Margin = new Thickness(0, 0, 0, 8) });
            var pw = new PasswordBox { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8) };
            var ok = new Button { Content = "Unlock", Width = 90, Margin = new Thickness(0, 12, 0, 0), HorizontalAlignment = HorizontalAlignment.Right, Background = B("#2d2f34"), Foreground = B("#e6e6e6") };
            ok.Click += (_, _) => { Value = pw.Password; DialogResult = true; Close(); };
            pw.KeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { Value = pw.Password; DialogResult = true; Close(); } };
            sp.Children.Add(pw); sp.Children.Add(ok); Content = sp; pw.Focus();
        }
    }
}
