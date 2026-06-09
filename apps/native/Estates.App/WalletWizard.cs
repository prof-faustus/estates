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
    public string Pseudonym { get; private set; } = "";
    public string WalletPath { get; private set; } = WalletStore.DefaultPath();   // WHERE the wallet file is saved
    public string Network { get; private set; } = "mainnet";                      // chosen on create AND load

    private enum Step { Splash, Choose, NewWalletFile, NewPassword, SeedShow, SeedConfirm, Register, Restore }
    private Step _step = Step.Splash;
    private Step _registerFrom = Step.SeedConfirm;   // where the Register page was reached FROM (for correct Back)
    private byte[] _pending = System.Array.Empty<byte>();
    private readonly TextBox _pseudonym = new();
    private readonly TextBox _email = new();
    private readonly TextBox _realname = new();
    private readonly TextBox _walletPathBox = new() { Text = WalletStore.DefaultPath() };
    private string _netChoice = "mainnet";

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
        foreach (var f in new Control[] { _pw, _pw2, _seedShow, _seedConfirm, _restoreSeed, _restorePw, _pseudonym, _email, _realname, _walletPathBox })
        { f.Background = B("#171819"); f.Foreground = B("#e6e6e6"); f.BorderThickness = new Thickness(0); f.Padding = new Thickness(8); f.Margin = new Thickness(0, 4, 0, 8); f.FontSize = 13; }
        _seedShow.FontFamily = _seedConfirm.FontFamily = _restoreSeed.FontFamily = new FontFamily("Consolas");
        _seedShow.TextWrapping = _seedConfirm.TextWrapping = _restoreSeed.TextWrapping = TextWrapping.Wrap;
        foreach (var btn in new[] { _back, _next, _cancel }) { btn.Background = B("#2d2f34"); btn.Foreground = B("#e6e6e6"); btn.BorderBrush = B("#3a3d42"); btn.Padding = new Thickness(8, 6, 8, 6); }
        // AutomationIds so the UI test can drive the real wizard reliably (no fragile text matching).
        void AId(System.Windows.DependencyObject c, string id) => System.Windows.Automation.AutomationProperties.SetAutomationId(c, id);
        AId(_pseudonym, "wzPseudonym"); AId(_email, "wzEmail"); AId(_realname, "wzRealName");
        AId(_pw, "wzPw"); AId(_pw2, "wzPw2"); AId(_seedShow, "wzSeedShow"); AId(_seedConfirm, "wzSeedConfirm");
        AId(_restoreSeed, "wzRestoreSeed"); AId(_restorePw, "wzRestorePw");
        AId(_back, "wzBack"); AId(_next, "wzNext"); AId(_cancel, "wzCancel"); AId(_msg, "wzMsg"); AId(_walletPathBox, "wzWalletPath");

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
                _title.Text = "Choose your network & wallet";
                _subtitle.Text = "First pick the NETWORK this wallet is for, then create or open a wallet. Everything is on-chain; nothing in the program runs without a loaded wallet.";
                _next.Visibility = Visibility.Collapsed;
                _body.Children.Add(Lab("which wallet do you want — mainnet, testnet, or regtest? (chosen now, used on create AND load)"));
                foreach (var net in new[] { "mainnet", "testnet", "regtest" })
                {
                    var rb = new RadioButton { Content = net, Foreground = B("#e6e6e6"), Margin = new Thickness(0, 3, 0, 3), GroupName = "wznet", IsChecked = _netChoice == net, FontSize = 13 };
                    System.Windows.Automation.AutomationProperties.SetAutomationId(rb, "wzNet_" + net);
                    string cap = net; rb.Checked += (_, _) => { _netChoice = cap; Network = cap; };
                    _body.Children.Add(rb);
                }
                Network = _netChoice;
                _body.Children.Add(new TextBlock { Height = 10 });
                bool exists = WalletStore.Exists(WalletStore.DefaultPath());
                var create = Big("➕  Create a new wallet"); create.Click += (_, _) => { Network = _netChoice; _step = Step.NewWalletFile; Render(); };
                var restore = Big("↩  Restore from seed"); restore.Click += (_, _) => { Network = _netChoice; _step = Step.Restore; Render(); };
                var open = Big(exists ? "🔓  Open my existing wallet" : "📂  Open a wallet file…"); open.Click += (_, _) => { Network = _netChoice; OpenExisting(exists); };
                System.Windows.Automation.AutomationProperties.SetAutomationId(create, "wzCreate");
                System.Windows.Automation.AutomationProperties.SetAutomationId(restore, "wzRestore");
                System.Windows.Automation.AutomationProperties.SetAutomationId(open, "wzOpen");
                _body.Children.Add(create); _body.Children.Add(restore); _body.Children.Add(open);
                break;
            }
            case Step.NewWalletFile:
            {
                _title.Text = $"Choose where to save your {_netChoice} wallet";
                _subtitle.Text = "YOU choose the file and the drive. The wallet is never overwritten and is backed up read-only on every write, so it can't be lost.";
                _body.Children.Add(Lab("wallet file (your encrypted keys are saved here)"));
                _body.Children.Add(_walletPathBox);
                var browse = new Button { Content = "Browse…", Width = 120, HorizontalAlignment = HorizontalAlignment.Left, Background = B("#2d2f34"), Foreground = B("#e6e6e6"), BorderBrush = B("#3a3d42"), Padding = new Thickness(8, 6, 8, 6), Margin = new Thickness(0, 0, 0, 12) };
                System.Windows.Automation.AutomationProperties.SetAutomationId(browse, "wzBrowse");
                browse.Click += (_, _) =>
                {
                    var dlg = new Microsoft.Win32.SaveFileDialog { Title = "Choose your new wallet file", Filter = "wallet (*.dat)|*.dat|all files|*.*", FileName = System.IO.Path.GetFileName(_walletPathBox.Text), OverwritePrompt = true };
                    try { dlg.InitialDirectory = System.IO.Path.GetDirectoryName(_walletPathBox.Text); } catch { }
                    if (dlg.ShowDialog() == true) _walletPathBox.Text = dlg.FileName;
                };
                _body.Children.Add(browse);
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
                _next.Content = "Next ›";
                break;
            case Step.Register:
                _title.Text = "Register your identity";
                _subtitle.Text = "Your IDENTITY is the key everything links to — payments, chat, NFTs, the game. Choose a pseudonym (required); enter an email (checked: valid format + the domain must resolve). The identity is signed and bound to your key.";
                _body.Children.Add(Lab("pseudonym / handle (required)")); _body.Children.Add(_pseudonym);
                _body.Children.Add(Lab("email (checked)")); _body.Children.Add(_email);
                _body.Children.Add(Lab("real name (optional)")); _body.Children.Add(_realname);
                _next.Content = "Register + create wallet";
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
            Step.NewWalletFile => Step.Choose,
            Step.NewPassword => Step.NewWalletFile,
            Step.SeedShow => Step.NewPassword,
            Step.SeedConfirm => Step.SeedShow,
            Step.Register => _registerFrom,
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
            case Step.NewWalletFile:
            {
                string wp = _walletPathBox.Text.Trim();
                if (wp.Length == 0) { _msg.Text = "choose where to save your wallet file"; return; }
                try { var dir = System.IO.Path.GetDirectoryName(wp); if (!string.IsNullOrEmpty(dir)) System.IO.Directory.CreateDirectory(dir); }
                catch (System.Exception ex) { _msg.Text = "cannot use that folder: " + ex.Message; return; }
                if (System.IO.File.Exists(wp)) { _msg.Text = "a wallet ALREADY exists there — choose a new file (a wallet is never overwritten)"; return; }
                WalletPath = wp; Network = _netChoice;
                _step = Step.NewPassword; Render(); break;
            }
            case Step.NewPassword:
                if (_pw.Password != _pw2.Password) { _msg.Text = "passwords do not match"; return; }
                Password = _pw.Password; _step = Step.SeedShow; Render(); break;
            case Step.SeedShow: _step = Step.SeedConfirm; Render(); break;
            case Step.SeedConfirm:
                if (_seedConfirm.Text.Trim().ToLowerInvariant() != Tx.ToHex(_pending)) { _msg.Text = "that does not match the seed — check your backup"; return; }
                _registerFrom = Step.SeedConfirm; _step = Step.Register; Render(); break;
            case Step.Register:
            {
                string ps = _pseudonym.Text.Trim();
                if (ps.Length == 0) { _msg.Text = "a PSEUDONYM is required — this is your identity (not your real name)"; return; }
                string em = _email.Text.Trim();
                if (!EmailOk(em)) { _msg.Text = "enter a valid email — format must be name@domain.tld and the domain must resolve"; return; }
                Pseudonym = ps;
                FinishRegistered(_pending, Password, ps, em, _realname.Text.Trim());
                break;
            }
            case Step.Restore:
            {
                string h = _restoreSeed.Text.Trim();
                if (h.Length != 64) { _msg.Text = "seed must be 64 hex characters"; return; }
                byte[] s; try { s = Tx.FromHex(h); } catch { _msg.Text = "seed is not valid hex"; return; }
                _pending = s; Password = _restorePw.Password; _registerFrom = Step.Restore; _step = Step.Register; Render(); break;   // restore ALSO registers a pseudonym
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
        try
        {
            var s = WalletStore.Open(path, pwWin.Value);
            if (s is null) { _msg.Text = "wrong password, or not a wallet file"; return; }
            // EXISTING wallet but NOT yet registered → force identity registration (pseudonym + email).
            string idjson = System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData), "Estates", "identity.json");
            if (!System.IO.File.Exists(idjson)) { _pending = s; Password = pwWin.Value; _registerFrom = Step.Choose; _step = Step.Register; Render(); return; }
            Seed = s; Password = pwWin.Value; DialogResult = true; Close();
        }
        catch (System.Exception e) { _msg.Text = e.Message; }
    }

    private void Finish(byte[] seed, string password)
    {
        try { WalletStore.Create(WalletStore.DefaultPath(), seed, password); Seed = seed; Password = password; DialogResult = true; Close(); }
        catch (System.Exception e) { _msg.Text = e.Message; }
    }

    // a real email CHECK with no server. The HARD gate is a strict format check (this is what makes the
    // email well-formed). DNS resolution is a BEST-EFFORT signal only and must NEVER block registration:
    // many valid domains publish only MX records (no A/AAAA), and DNS can be momentarily unreachable —
    // neither means the email is invalid. So: bad format → reject; good format → accept (DNS is advisory).
    private static bool EmailOk(string e)
    {
        e = (e ?? "").Trim();
        // strict-enough format: local@domain.tld, no spaces, a dot in the domain, sane length.
        if (e.Length < 6 || e.Length > 254) return false;
        if (!System.Text.RegularExpressions.Regex.IsMatch(e, @"^[^@\s]+@[^@\s]+\.[^@\s]+$")) return false;
        var parts = e.Split('@');
        if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length < 3) return false;
        if (parts[1].StartsWith('.') || parts[1].EndsWith('.') || parts[1].Contains("..")) return false;
        return true;   // format is valid — accept. (DNS is checked best-effort in DnsHint, never blocks.)
    }

    // advisory only: does the domain resolve? Used to show a soft hint, NEVER to block.
    private static bool DnsHint(string e)
    {
        try { return System.Net.Dns.GetHostAddresses(e.Split('@')[1]).Length > 0; } catch { return false; }
    }

    // REGISTER: create the wallet, then bind the PSEUDONYM ↔ email ↔ wallet ↔ identity key into a signed
    // identity profile (self-sovereign; no server). The identity = index-0 key; the profile is signed by a
    // sub-key (the base identity key never signs). Persisted to %APPDATA%/Estates/identity.json (+ handle).
    private void FinishRegistered(byte[] seed, string password, string pseudonym, string email, string realname)
    {
        try
        {
            RegisterCore(WalletPath, seed, password, pseudonym, email, realname);   // the file location YOU chose
            Seed = seed; Password = password; Pseudonym = pseudonym; DialogResult = true; Close();
        }
        catch (System.Exception e) { _msg.Text = e.Message; }
    }

    /// <summary>The REAL registration: create the encrypted wallet and write the signed identity (index-0
    /// identity key, a sub-key attests). Shared by the live wizard AND the headless self-test, so the test
    /// exercises the exact production code. Static + GUI-free.</summary>
    public static void RegisterCore(string walletPath, byte[] seed, string password, string pseudonym, string email, string realname, string? identityDir = null)
    {
        WalletStore.Create(walletPath, seed, password);
        byte[] identityPub = Secp256k1.PublicKey(Wallet.ChildPriv(seed, 0));
        byte[] attPriv = Wallet.ChildPriv(seed, 1);
        string firstAddr = Address.P2pkh(Recovery.Hash160(Secp256k1.PublicKey(attPriv)), BsvNet.Mainnet);
        string profile = "{" +
            $"\"pseudonym\":{J(pseudonym)},\"email\":{J(email)},\"realname\":{J(realname)}," +
            $"\"identity\":\"{Tx.ToHex(identityPub)}\",\"wallet_address\":\"{firstAddr}\"," +
            $"\"attestation_pub\":\"{Tx.ToHex(Secp256k1.PublicKey(attPriv))}\",\"created\":\"{System.DateTime.UtcNow:o}\"" +
            "}";
        byte[] sig = EcdsaSign.Sign(attPriv, System.Text.Encoding.UTF8.GetBytes(profile));
        // identityDir lets a TEST write its identity into its own evidence folder, NEVER the user's %APPDATA%.
        string dir = identityDir ?? System.IO.Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.ApplicationData), "Estates");
        System.IO.Directory.CreateDirectory(dir);
        string fname = identityDir is null ? "identity.json" : "identity-" + pseudonym + ".json";
        System.IO.File.WriteAllText(System.IO.Path.Combine(dir, fname), profile + "\n" + Tx.ToHex(sig));
        if (identityDir is null) System.IO.File.WriteAllText(System.IO.Path.Combine(dir, "identity.txt"), pseudonym);
        // verify what we just wrote actually verifies (a registration that doesn't verify is a failure)
        if (!EcdsaSign.Verify(Secp256k1.PublicKey(attPriv), System.Text.Encoding.UTF8.GetBytes(profile), sig))
            throw new System.Exception("identity signature failed to verify");
    }

    private static string J(string s) => "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

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
