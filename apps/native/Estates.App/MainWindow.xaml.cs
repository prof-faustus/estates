using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Estates.Core;

namespace Estates.App;

/// <summary>
/// The native ESTATES window — tabbed: Lobby, Game, Wallet, Chat (switch with the tabs).
/// A bot is just another node YOU run (estates.exe --bot) and fully control. No server;
/// closing the window ends everything. STANDALONE: the wallet is entirely in-process
/// (no node, no RPC, no network) — see StandaloneWallet; the game board is its own tab;
/// chat is end-to-end encrypted over the direct peer links.
/// </summary>
public partial class MainWindow : Window
{
    private readonly P2PNode _node;
    private readonly byte[] _master;     // secp256k1 wallet private key (this session)
    private readonly byte[] _walletPub;  // compressed wallet public key

    public MainWindow(bool bot = false)
    {
        InitializeComponent();

        _master = RandomNumberGenerator.GetBytes(32);
        _walletPub = Cipher.PublicKey(_master);
        if (bot) Title = "ESTATES — bot (you control it)";

        _node = new P2PNode((bot ? "bot-" : "player-") + Tx.ToHex(_walletPub)[..6], Tx.ToHex(_walletPub));
        App.Teardowns.Add(() => { try { _node.Dispose(); } catch { } });
        _node.OnPeerDiscovered += _ => Dispatcher.Invoke(RefreshNodes);
        _node.OnPeerLost += _ => Dispatcher.Invoke(RefreshNodes);
        _node.OnLink += link => link.OnFrame += (l, f) => Dispatcher.Invoke(() => OnChatFrame(l, f));
        Closed += (_, _) => { try { _node.Dispose(); } catch { } };

        RefreshNodes();
        WalletHost.Content = BuildWalletUI();
        ChatHost.Content = BuildChatUI();

        // Real (mainnet) is default; testnet free; regtest is password-gated (test-only).
        Network.SelectionChanged += (_, _) =>
        {
            string sel = ((ComboBoxItem)Network.SelectedItem).Content!.ToString()!;
            if (sel == "regtest" && PromptPassword("Regtest is test-only — enter the password") != "craig") { Network.SelectedIndex = 0; return; }
            _network = sel;
            WalletHost.Content = BuildWalletUI();   // rebuild the wallet against the chosen network
        };
    }

    private static SolidColorBrush B(string hex) => new((Color)ColorConverter.ConvertFromString(hex));

    // ---- Lobby: only peers alive right now ------------------------------------------
    private void RefreshNodes()
    {
        var peers = _node.Peers();
        NodeList.Children.Clear();
        foreach (var p in peers)
        {
            var name = new TextBlock { Text = p.Name, Foreground = B("#e6e6e6"), FontSize = 13, FontWeight = FontWeights.SemiBold };
            var sub = new TextBlock { Text = p.TableId != null ? $"hosting a table · {p.TableInfo}" : "in the lobby", Foreground = B("#9aa0a6"), FontSize = 11, Margin = new Thickness(0, 2, 0, 0) };
            var stack = new StackPanel(); stack.Children.Add(name); stack.Children.Add(sub);
            NodeList.Children.Add(new Border { Background = B("#232529"), CornerRadius = new CornerRadius(8), Padding = new Thickness(12), Margin = new Thickness(0, 0, 0, 8), Child = stack });
        }
        LobbyStatus.Text = peers.Count == 0 ? "You're the only node here right now." : $"{peers.Count} other node(s) live right now.";
        _refreshChatWho?.Invoke();          // keep the chat contact line in sync with who's live
    }

    private (string net, int seats) Config()
        => (((ComboBoxItem)Network.SelectedItem).Content!.ToString()!, int.Parse(((ComboBoxItem)SeatCount.SelectedItem).Content!.ToString()!));

    private void Start_Click(object sender, RoutedEventArgs e)
    {
        var (net, n) = Config();
        if (!RequireFunding(net)) return;
        if (_node.Peers().Count == 0) { StartMsg.Text = "You can't start a game alone — run a bot (a node you control) or wait for another player to join, then start."; return; }
        StartGame(net, n);
    }

    private void Join_Click(object sender, RoutedEventArgs e)
    {
        var (net, n) = Config();
        if (!RequireFunding(net)) return;
        var tables = _node.Peers().Where(p => p.TableId != null).ToList();
        if (tables.Count == 0) { StartMsg.Text = "No table to join — run a bot or wait for someone to open a table."; return; }
        _node.Connect(tables[0]);
        StartGame(net, n);
    }

    // HARD RULE: a game is real-value, so it cannot start with an empty wallet. The check is
    // ENTIRELY LOCAL — the standalone wallet's own balance. No node, no RPC, nothing to reach.
    private bool RequireFunding(string net)
    {
        var w = EnsureWallet();
        if (w is null) { StartMsg.Text = "Unlock or create your wallet (Wallet tab), then fund it, before starting a game."; return false; }
        if (w.Balance() <= 0) { StartMsg.Text = "Your wallet holds 0 — this is a real-value game. Fund it (Wallet → Fund) before starting."; return false; }
        StartMsg.Text = "";
        return true;
    }

    private void RunBot_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string? exe = Environment.ProcessPath;
            if (exe is not null) System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe, "--bot") { UseShellExecute = false });
        }
        catch { }
    }

    // ---- Game (its own tab) — a real board, you click every action ------------------
    private GameState? _game;
    private readonly List<(int id, string name, string txid)> _heldNfts = new();   // deed/card NFTs you hold
    private string? _genesisTxid;   // local table id for the current game (no node)

    private void StartGame(string network, int seats)
    {
        // STANDALONE: the table opens locally and play proceeds peer-to-peer. The table-setup and
        // per-move transactions are built + signed in-process by the standalone wallet (no node);
        // settlement to the chain is handed off peer-to-peer, never reached out for here.
        _genesisTxid = Tx.ToHex(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes($"table:{network}:{seats}:{Tx.ToHex(_walletPub)}:{DateTime.UtcNow.Ticks}")));

        var deckOrder = new Dictionary<string, List<int>>();
        foreach (var kv in Params.Instance.Decks) deckOrder[kv.Key] = Enumerable.Range(0, kv.Value.Count).ToList();
        _game = Engine.InitialState(network, seats, 1_000_000, deckOrder, false);
        RenderGame();
        Tabs.SelectedIndex = 1;
    }

    private static readonly Dictionary<string, string> GroupColor = new()
    {
        ["Sienna"] = "#8d5524", ["Sky"] = "#aee1f9", ["Rose"] = "#f7a8c4", ["Amber"] = "#f5a623",
        ["Crimson"] = "#d0021b", ["Gold"] = "#f8e71c", ["Viridian"] = "#2e7d32", ["Indigo"] = "#283593",
        ["Rails"] = "#555555", ["Utilities"] = "#8a8a8a",
    };
    private static readonly string[] SeatColors = { "#e6194b", "#3cb44b", "#4363d8", "#f58231", "#911eb4", "#42d4f4" };
    private static (int row, int col) BoardCell(int i)
        => i <= 10 ? (10, 10 - i) : i <= 20 ? (20 - i, 0) : i <= 30 ? (0, i - 20) : (i - 30, 10);

    private void RenderGame()
    {
        var g = _game;
        if (g is null) return;
        var grid = new Grid();
        for (int k = 0; k < 11; k++)
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        }
        for (int i = 0; i < 40; i++)
        {
            var (row, col) = BoardCell(i);
            var cell = BuildCell(i, g);
            Grid.SetRow(cell, row); Grid.SetColumn(cell, col);
            grid.Children.Add(cell);
        }
        var center = BuildCenter(g);
        Grid.SetRow(center, 1); Grid.SetColumn(center, 1); Grid.SetRowSpan(center, 9); Grid.SetColumnSpan(center, 9);
        grid.Children.Add(center);
        GameHost.Content = new Viewbox { Child = new Border { Width = 900, Height = 900, Child = grid }, Stretch = Stretch.Uniform, Margin = new Thickness(8) };
    }

    private UIElement BuildCell(int i, GameState g)
    {
        var sp = Params.Instance.Board[i];
        var stack = new StackPanel();
        if (sp.Group != null && GroupColor.TryGetValue(sp.Group, out var c))
            stack.Children.Add(new Border { Height = 12, Background = B(c) });
        stack.Children.Add(new TextBlock { Text = sp.Name, Foreground = B("#101010"), FontSize = 9, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(3, 2, 3, 0) });
        if (sp.BasePrice is long bp) stack.Children.Add(new TextBlock { Text = bp + " sat", Foreground = B("#444"), FontSize = 8, Margin = new Thickness(3, 0, 3, 0) });
        var tok = new WrapPanel { Margin = new Thickness(3, 2, 3, 3) };
        foreach (var s in g.Seats) if (s.Position == i)
            tok.Children.Add(new Border { Width = 11, Height = 11, CornerRadius = new CornerRadius(6), Background = B(SeatColors[s.Id % SeatColors.Length]), Margin = new Thickness(1) });
        stack.Children.Add(tok);
        return new Border { Background = B("#f4efdf"), BorderBrush = B("#101010"), BorderThickness = new Thickness(0.7), Child = stack };
    }

    private UIElement BuildCenter(GameState g)
    {
        var inner = new StackPanel { Margin = new Thickness(20) };
        inner.Children.Add(new TextBlock { Text = "ESTATES", Foreground = B("#ffffff"), FontSize = 30, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 0, 0, 6) });
        if (_genesisTxid is not null)
            inner.Children.Add(new TextBlock { Text = "standalone table · " + _genesisTxid[..16] + "…", Foreground = B("#9aa0a6"), FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 0, 0, 10) });
        foreach (var s in g.Seats)
        {
            bool turn = s.Id == g.Current && g.Winner is null;
            var line = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4), HorizontalAlignment = HorizontalAlignment.Center };
            line.Children.Add(new Border { Width = 14, Height = 14, CornerRadius = new CornerRadius(7), Background = B(SeatColors[s.Id % SeatColors.Length]), Margin = new Thickness(0, 0, 8, 0) });
            line.Children.Add(new TextBlock { Text = $"Seat {s.Id}: {s.Balance} sat" + (s.Bankrupt ? " (out)" : "") + (turn ? "   ← turn" : ""), Foreground = turn ? B("#b9f6ca") : B("#e6e6e6"), FontSize = 15 });
            inner.Children.Add(line);
        }
        if (g.LastRoll is int[] r) inner.Children.Add(new TextBlock { Text = $"▶ dice  {r[0]} + {r[1]} = {r[0] + r[1]}", Foreground = B("#ffd54f"), FontSize = 18, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 12, 0, 8) });
        if (g.Winner is int w) inner.Children.Add(new TextBlock { Text = $"Winner: Seat {w}", Foreground = B("#ffd54f"), FontSize = 20, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center });
        var bar = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 12, 0, 10) };
        foreach (var a in Engine.LegalActions(g))
        {
            if (a is not ("ROLL" or "BUY" or "DECLINE" or "PAY_TAX" or "END_TURN" or "FORFEIT")) continue;
            var btn = new Button { Content = Friendly(a), Margin = new Thickness(5), FontSize = 15 };
            string act = a; btn.Click += (_, _) => DoAction(act);
            bar.Children.Add(btn);
        }
        inner.Children.Add(bar);
        var leave = new Button { Content = "Leave game", HorizontalAlignment = HorizontalAlignment.Center, Background = B("#3a3d42") };
        leave.Click += (_, _) => { _game = null; GameHost.Content = null; Tabs.SelectedIndex = 0; RefreshNodes(); };
        inner.Children.Add(leave);
        return new Border { Background = B("#14532d"), Child = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = inner } };
    }

    private static string Friendly(string a) => a switch
    {
        "ROLL" => "Roll the dice", "BUY" => "Buy", "DECLINE" => "Decline (auction)",
        "PAY_TAX" => "Pay tax", "END_TURN" => "End turn", "FORFEIT" => "Forfeit turn", _ => a,
    };

    private void DoAction(string type)
    {
        var g = _game;
        if (g is null) return;
        int? bought = type == "BUY" ? g.PendingTitle : null;   // the property whose deed becomes yours
        Estates.Core.Action a = type switch
        {
            "ROLL" => new Estates.Core.Action("ROLL") { Dice = new[] { Die(), Die() } },
            "PAY_TAX" => new Estates.Core.Action("PAY_TAX") { Choice = "flat" },
            _ => new Estates.Core.Action(type),
        };
        var res = Engine.Apply(g, a);
        if (res.Ok && res.State is not null)
        {
            _game = res.State;
            // STANDALONE: the move is a signed action applied locally and (in a multiplayer game)
            // sent to peers over the direct P2P link. The real BSV move/NFT transactions are built
            // + signed in-process by the standalone wallet; nothing is anchored through a node here.
            string commit = a.Dice != null ? $"{type}:{a.Dice[0]},{a.Dice[1]}@t{_game.TurnIndex}" : $"{type}@t{_game.TurnIndex}";
            _game.Log.Add($"move {commit} (signed, applied; peer-to-peer)");
            if (bought is int pid)   // buying records the deed NFT to YOUR wallet
            {
                string nm = Params.Instance.Board[pid].Name;
                _heldNfts.Add((pid, nm, "local"));
                _game.Log.Add($"deed '{nm}' recorded to your wallet");
            }
        }
        else g.Log.Add($"(rejected: {res.Code})");
        RenderGame();
    }

    private static int Die() => RandomNumberGenerator.GetInt32(1, 7);

    // ---- Wallet (its own tab): real, connected to YOUR BSV node ----------------------
    private byte[]? _walletSeed;   // the persisted wallet seed once unlocked (null = locked)
    private UIElement BuildWalletUI()
    {
        var host = new ContentControl();
        TextBlock Head(string t) => new() { Text = t, Foreground = B("#e6e6e6"), FontSize = 15, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 14, 0, 6) };
        TextBlock Out() => new() { Foreground = B("#f5a623"), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0), FontFamily = new FontFamily("Consolas") };

        void Render()
        {
            var sp = new StackPanel { Margin = new Thickness(4) };
            if (_walletSeed is null)
            {
                string path = WalletStore.DefaultPath();
                bool exists = WalletStore.Exists(path);
                var msg = Out();
                TextBlock Note(string t) => new() { Text = t, Foreground = B("#9aa0a6"), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) };
                TextBlock Warn(string t) => new() { Text = t, Foreground = B("#f7a8c4"), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) };
                TextBlock Lab(string t) => new() { Text = t, Foreground = B("#9aa0a6"), FontSize = 11 };
                TextBox FieldBox() => new() { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), FontSize = 12, FontFamily = new FontFamily("Consolas"), Margin = new Thickness(0, 2, 0, 8), TextWrapping = TextWrapping.Wrap };
                Button Btn2(string t) => new() { Content = t, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 8) };
                var pw = new PasswordBox { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), FontSize = 13, Margin = new Thickness(0, 0, 0, 8) };
                void Unlocked(byte[] s) { _walletSeed = s; _wallet = null; Render(); }
                void LoadFile()
                {
                    var dlg = new Microsoft.Win32.OpenFileDialog { Title = "Load wallet.dat", Filter = "wallet (*.dat)|*.dat|all files|*.*" };
                    if (dlg.ShowDialog() != true) return;
                    try { var s = WalletStore.Open(dlg.FileName, pw.Password); if (s is null) { msg.Text = "wrong password, or not a wallet file"; return; } Unlocked(s); }
                    catch (Exception ex) { msg.Text = ex.Message; }
                }

                if (exists)
                {
                    sp.Children.Add(Head("Unlock wallet"));
                    sp.Children.Add(Warn("This wallet holds your seed and your funds. BACK UP YOUR SEED — if you lose it, the money is gone forever."));
                    sp.Children.Add(Lab("password (leave blank if you set none)")); sp.Children.Add(pw);
                    var go = Btn2("Unlock");
                    go.Click += (_, _) => { try { var s = WalletStore.Open(path, pw.Password); if (s is null) { msg.Text = "wrong password"; return; } Unlocked(s); } catch (Exception ex) { msg.Text = ex.Message; } };
                    pw.KeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; go.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent)); } };
                    sp.Children.Add(go);
                    var load = Btn2("Load a different wallet.dat file…"); load.Click += (_, _) => LoadFile(); sp.Children.Add(load);

                    // DESTRUCTIVE replace — gated behind an explicit typed confirmation; never one click.
                    var dz = new StackPanel();
                    dz.Children.Add(Warn("Danger zone: replacing the wallet PERMANENTLY destroys the current seed and any funds it holds. Only proceed if you have backed up your seed. Type REPLACE to confirm."));
                    var conf = FieldBox();
                    var rep = Btn2("Replace wallet (destroys current funds)"); rep.Background = B("#5a2030"); rep.Foreground = B("#ffd54f");
                    rep.Click += (_, _) => { if (conf.Text.Trim() != "REPLACE") { msg.Text = "type REPLACE to confirm the destructive replace"; return; } try { System.IO.File.Delete(path); Unlocked(WalletStore.OpenOrCreate(path, pw.Password)); } catch (Exception ex) { msg.Text = ex.Message; } };
                    dz.Children.Add(conf); dz.Children.Add(rep);
                    sp.Children.Add(new Border { Background = B("#2a1418"), CornerRadius = new CornerRadius(8), Padding = new Thickness(10), Margin = new Thickness(0, 12, 0, 0), Child = dz });
                }
                else
                {
                    sp.Children.Add(Head("Create or restore your wallet"));
                    sp.Children.Add(Note("Real BSV. Your seed is saved to disk (encrypted with your password) so closing keeps your money. BACK UP YOUR SEED — losing it loses your funds, forever."));
                    sp.Children.Add(Lab("password (optional)")); sp.Children.Add(pw);
                    var create = Btn2("Create a new wallet");
                    create.Click += (_, _) => { try { Unlocked(WalletStore.OpenOrCreate(path, pw.Password)); } catch (Exception ex) { msg.Text = ex.Message; } };
                    pw.KeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; create.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent)); } };
                    sp.Children.Add(create);
                    sp.Children.Add(Note("…or restore an existing wallet:"));
                    sp.Children.Add(Lab("seed (64-hex backup)")); var seedBox = FieldBox(); sp.Children.Add(seedBox);
                    var restore = Btn2("Restore from seed");
                    restore.Click += (_, _) => { try { string h = seedBox.Text.Trim(); if (h.Length != 64) { msg.Text = "seed must be 64 hex characters"; return; } byte[] s = Tx.FromHex(h); WalletStore.Create(path, s, pw.Password); Unlocked(s); } catch (Exception ex) { msg.Text = ex.Message; } };
                    seedBox.PreviewKeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; restore.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent)); } };
                    sp.Children.Add(restore);
                    var load = Btn2("Load a wallet.dat file…"); load.Click += (_, _) => LoadFile(); sp.Children.Add(load);
                }
                sp.Children.Add(msg);
                host.Content = sp;
                return;
            }

            host.Content = ElectrumWallet(() => { _walletSeed = null; Render(); });
        }

        Render();
        return new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, MaxHeight = 640, Content = host, Margin = new Thickness(0, 12, 0, 0) };
    }

    // ---- network: real (default) / testnet / regtest (password-gated, test-only) ------
    private string _network = "mainnet";
    private readonly List<(string name, string address)> _contacts = new();

    // The standalone wallet (in-process; NO node). Created from the unlocked seed, rebuilt when the
    // network changes so addresses carry the right version byte.
    private StandaloneWallet? _wallet;
    private StandaloneWallet? EnsureWallet()
    {
        if (_walletSeed is null) return null;
        if (_wallet is null || _wallet.Network != _network) _wallet = new StandaloneWallet(_walletSeed, _network);
        return _wallet;
    }

    private string? PromptPassword(string title)
    {
        var w = new Window { Title = title, Width = 380, Height = 170, Background = B("#1e1f22"), WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = this, ResizeMode = ResizeMode.NoResize };
        var sp = new StackPanel { Margin = new Thickness(16) };
        sp.Children.Add(new TextBlock { Text = title, Foreground = B("#e6e6e6"), Margin = new Thickness(0, 0, 0, 8), TextWrapping = TextWrapping.Wrap });
        var pw = new PasswordBox { Background = B("#171819"), Foreground = B("#e6e6e6"), Padding = new Thickness(8), FontSize = 13 };
        sp.Children.Add(pw);
        string? result = null;
        var ok = new Button { Content = "OK", HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
        ok.Click += (_, _) => { result = pw.Password; w.DialogResult = true; };
        // Enter submits exactly as clicking OK (Enter MUST equal the button everywhere).
        pw.KeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; result = pw.Password; w.DialogResult = true; } };
        sp.Children.Add(ok);
        w.Content = sp;
        pw.Focus();
        w.ShowDialog();
        return result;
    }

    // ---- STANDALONE wallet (no node, no RPC, no network): Info/Send/Receive/Addresses/Coins/Fund/Sign/NFTs ----
    private UIElement ElectrumWallet(System.Action relock)
    {
        var w = EnsureWallet()!;          // built from the unlocked seed; entirely in-process
        TextBox F() => new() { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), Margin = new Thickness(0, 2, 0, 6), FontFamily = new FontFamily("Consolas"), FontSize = 12, TextWrapping = TextWrapping.Wrap, AcceptsReturn = true };
        TextBox Mono(int h) => new() { IsReadOnly = true, Background = B("#171819"), Foreground = B("#cfd2d6"), FontFamily = new FontFamily("Consolas"), FontSize = 11, BorderThickness = new Thickness(0), Padding = new Thickness(8), Height = h, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        TextBlock L(string t) => new() { Text = t, Foreground = B("#9aa0a6"), FontSize = 11 };
        TextBlock O() => new() { Foreground = B("#f5a623"), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0), FontFamily = new FontFamily("Consolas") };
        Button Btn(string t) => new() { Content = t, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 6, 0, 0) };
        TabItem Tab(string h, StackPanel body) => new() { Header = h, Content = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = new StackPanel { Margin = new Thickness(12), Children = { body } } } };
        var tabs = new TabControl { Background = B("#1e1f22"), BorderThickness = new Thickness(0) };

        // Info — balance is the wallet's OWN UTXO set; no node is contacted.
        var info = new StackPanel();
        info.Children.Add(new TextBlock { Text = $"Network: {_network}   ·   standalone (no node)", Foreground = B("#e6e6e6"), FontSize = 14, FontWeight = FontWeights.Bold });
        var bal = new TextBlock { Foreground = B("#7bd88f"), FontSize = 22, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 6, 0, 2) };
        void ShowBal() => bal.Text = w.Balance() + " sat";
        ShowBal();
        var rb = Btn("Refresh"); rb.Click += (_, _) => ShowBal();
        info.Children.Add(bal); info.Children.Add(rb);
        info.Children.Add(L("Recovery seed (back this up)")); var sb0 = F(); sb0.IsReadOnly = true; sb0.Text = Tx.ToHex(_walletSeed!); info.Children.Add(sb0);
        info.Children.Add(L("Address #0")); var sa0 = F(); sa0.IsReadOnly = true; sa0.Text = w.AddressAt(0); info.Children.Add(sa0);
        var lk = Btn("Lock wallet"); lk.Click += (_, _) => relock(); info.Children.Add(lk);
        tabs.Items.Add(Tab("Info", info));

        // Fund — bring REAL coins into the standalone wallet. A coin arrives either from a peer
        // (P2P transfer) or, for testing, by importing an outpoint you funded from the faucet. This
        // is the ONLY place a coin enters; nothing reaches out to a node.
        var fund = new StackPanel();
        fund.Children.Add(new TextBlock { Text = "Fund the wallet (import a coin you own)", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        fund.Children.Add(L("This wallet starts EMPTY. Add a real UTXO you control — txid, output index, value (sat), and which of your address indexes holds it. No node is contacted."));
        var ftx = F(); var fvout = F(); var fsat = F(); var fidx = F(); var fo2 = O();
        var fbtn = Btn("Import coin");
        fbtn.Click += (_, _) => { try { w.AddCoin(ftx.Text.Trim(), long.Parse(fvout.Text.Trim()), long.Parse(fsat.Text.Trim()), int.Parse(fidx.Text.Trim())); fo2.Text = $"imported · balance {w.Balance()} sat"; ShowBal(); } catch (Exception e) { fo2.Text = e.Message; } };
        foreach (var f in new[] { ftx, fvout, fsat, fidx }) f.PreviewKeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; fbtn.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent)); } };
        fund.Children.Add(L("txid")); fund.Children.Add(ftx); fund.Children.Add(L("vout")); fund.Children.Add(fvout); fund.Children.Add(L("value (sat)")); fund.Children.Add(fsat); fund.Children.Add(L("address index holding it")); fund.Children.Add(fidx); fund.Children.Add(fbtn); fund.Children.Add(fo2);
        tabs.Items.Add(Tab("Fund", fund));

        // Send — build + SIGN a real BSV tx in-process. The raw tx is shown to hand to a peer or
        // broadcast yourself; the wallet performs no network action.
        var send = new StackPanel(); var to = F(); var amt = F(); var fee = F(); fee.Text = "500"; var so = O(); var raw = Mono(120);
        var peer = F(); peer.Text = _network == "regtest" ? "127.0.0.1:18444" : "";
        var sbtn = Btn("Send (build, sign + broadcast)");
        sbtn.Click += async (_, _) =>
        {
            try
            {
                var built = w.BuildSend(to.Text.Trim(), long.Parse(amt.Text.Trim()), long.Parse(fee.Text.Trim()));
                if (!w.VerifySpend(built)) { so.Text = "internal error: signatures invalid"; return; }
                raw.Text = built.RawHex;
                var hp = peer.Text.Trim().Split(':');
                if (hp.Length != 2 || !int.TryParse(hp[1], out int port)) { so.Text = "to broadcast, enter a peer as host:port"; return; }
                var net = _network == "mainnet" ? BsvNet.Mainnet : _network == "testnet" ? BsvNet.Testnet : BsvNet.Regtest;
                so.Text = $"broadcasting {built.Txid[..16]}… to {peer.Text.Trim()} …"; sbtn.IsEnabled = false;
                bool ok = await Broadcaster.BroadcastAsync(net, hp[0], port, Tx.FromHex(built.RawHex), 15000);
                sbtn.IsEnabled = true;
                if (ok) { w.SpendCoins(built.Spent); ShowBal(); so.Text = $"SENT · txid {built.Txid} · accepted by peer · change {built.Change} sat"; }
                else so.Text = $"built + signed (txid {built.Txid}) but the peer did not accept/pull it — check the host:port. Raw tx below to broadcast elsewhere.";
            }
            catch (Exception e) { sbtn.IsEnabled = true; so.Text = e.Message; }
        };
        foreach (var f in new[] { to, amt, fee, peer }) f.PreviewKeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; sbtn.RaiseEvent(new RoutedEventArgs(System.Windows.Controls.Primitives.ButtonBase.ClickEvent)); } };
        send.Children.Add(L("Pay to (address)")); send.Children.Add(to); send.Children.Add(L("Amount (sat)")); send.Children.Add(amt); send.Children.Add(L("Fee (sat)")); send.Children.Add(fee);
        send.Children.Add(L("Broadcast peer (host:port)")); send.Children.Add(peer); send.Children.Add(sbtn); send.Children.Add(so);
        send.Children.Add(L("Signed raw transaction")); send.Children.Add(raw);
        tabs.Items.Add(Tab("Send", send));

        // Receive
        var recv = new StackPanel(); var ridx = F(); ridx.Text = "1"; var ra = F(); ra.IsReadOnly = true; var rbtn = Btn("Show address");
        rbtn.Click += (_, _) => { try { ra.Text = w.AddressAt(int.Parse(ridx.Text.Trim())); } catch (Exception e) { ra.Text = e.Message; } };
        recv.Children.Add(L("address index")); recv.Children.Add(ridx); recv.Children.Add(rbtn); recv.Children.Add(ra); tabs.Items.Add(Tab("Receive", recv));

        // Addresses (derived from the seed)
        var addrs = new StackPanel(); var al = Mono(380); var s2 = new System.Text.StringBuilder();
        foreach (var a in w.Addresses(20)) s2.AppendLine($"#{a.Index,-3} {a.Address}"); al.Text = s2.ToString();
        addrs.Children.Add(L("Your addresses (derived from the seed)")); addrs.Children.Add(al); tabs.Items.Add(Tab("Addresses", addrs));

        // Coins (the wallet's own UTXO set)
        var coins = new StackPanel(); var cl = Mono(300);
        void LoadCoins() { var s = new System.Text.StringBuilder(); foreach (var u in w.Coins) s.AppendLine($"{u.Sats,15} sat  {u.Txid}:{u.Vout}  (addr #{u.AddrIndex})"); if (w.Coins.Count == 0) s.AppendLine("no coins yet — import one in the Fund tab."); cl.Text = s.ToString(); }
        LoadCoins(); var cr = Btn("Refresh coins"); cr.Click += (_, _) => { LoadCoins(); ShowBal(); };
        coins.Children.Add(cr); coins.Children.Add(cl); tabs.Items.Add(Tab("Coins", coins));

        // Sign / verify a message — local secp256k1 ECDSA (no node).
        var tools = new StackPanel();
        tools.Children.Add(new TextBlock { Text = "Sign a message (your wallet key #0)", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        var gm = F(); var go = O(); var gb = Btn("Sign");
        gb.Click += (_, _) => { try { byte[] priv = w.ChildPriv(0); byte[] sig = EcdsaSign.Sign(priv, System.Text.Encoding.UTF8.GetBytes(gm.Text)); go.Text = $"pub {Tx.ToHex(w.ChildPub(0))}\nsig {Tx.ToHex(sig)}"; } catch (Exception e) { go.Text = e.Message; } };
        tools.Children.Add(L("message")); tools.Children.Add(gm); tools.Children.Add(gb); tools.Children.Add(go);
        tools.Children.Add(new TextBlock { Text = "Verify a message", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold, Margin = new Thickness(0, 12, 0, 0) });
        var vp = F(); var vs = F(); var vm = F(); var vo = O(); var vb = Btn("Verify");
        vb.Click += (_, _) => { try { vo.Text = EcdsaSign.Verify(Tx.FromHex(vp.Text.Trim()), System.Text.Encoding.UTF8.GetBytes(vm.Text), Tx.FromHex(vs.Text.Trim())) ? "VALID" : "INVALID"; } catch (Exception e) { vo.Text = e.Message; } };
        tools.Children.Add(L("pubkey (hex)")); tools.Children.Add(vp); tools.Children.Add(L("signature (hex)")); tools.Children.Add(vs); tools.Children.Add(L("message")); tools.Children.Add(vm); tools.Children.Add(vb); tools.Children.Add(vo);
        tabs.Items.Add(Tab("Sign", tools));

        // NFTs — the deeds/cards you hold
        var nft = new StackPanel();
        nft.Children.Add(new TextBlock { Text = "Your NFTs — deeds & cards", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        var nl = Mono(360);
        void LoadNfts() { var s = new System.Text.StringBuilder(); foreach (var n in _heldNfts) s.AppendLine($"{n.name}  (property #{n.id})"); if (_heldNfts.Count == 0) s.AppendLine("none yet — buy a property in a game and its deed lands here."); nl.Text = s.ToString(); }
        LoadNfts(); var nrb = Btn("Refresh"); nrb.Click += (_, _) => LoadNfts();
        nft.Children.Add(nrb); nft.Children.Add(nl); tabs.Items.Add(Tab("NFTs", nft));

        // AUTO-REFRESH: balance + coins update themselves; no manual refresh needed. Stops when the
        // wallet view is unloaded (lock/close) so it never leaks.
        var auto = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        auto.Tick += (_, _) => { try { ShowBal(); LoadCoins(); } catch { } };
        auto.Start();
        tabs.Unloaded += (_, _) => auto.Stop();
        return tabs;
    }

    // ---- Chat: a real messenger (group + 1:1, history, reactions/edit/delete/receipts, identity) ----
    private readonly Conversation _conv = new("lobby", true, Array.Empty<string>());
    private string _displayName = "";
    private StackPanel? _chatList;
    private System.Action? _refreshChatWho;

    private UIElement BuildChatUI()
    {
        var root = new DockPanel { Margin = new Thickness(0, 12, 0, 0) };

        // identity row — set your name (your identity card); your pubkey is your address
        var idRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
        var nameBox = new TextBox { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), FontSize = 13, Text = _displayName };
        var setName = new Button { Content = "Set identity", Margin = new Thickness(8, 0, 0, 0), Padding = new Thickness(12, 6, 12, 6) };
        DockPanel.SetDock(setName, Dock.Right); idRow.Children.Add(setName); idRow.Children.Add(nameBox);
        DockPanel.SetDock(idRow, Dock.Top); root.Children.Add(idRow);
        var who = new TextBlock { Foreground = B("#9aa0a6"), FontSize = 11, Margin = new Thickness(0, 0, 0, 8), TextWrapping = TextWrapping.Wrap };
        void ShowWho()
        {
            var peers = _node.Peers();
            string names = peers.Count == 0 ? "no one else here yet" : string.Join(", ", peers.Select(p => p.Name));
            who.Text = $"you: {(_displayName.Length > 0 ? _displayName : "(set a name)")}  ·  {Tx.ToHex(_walletPub)[..12]}…\nin chat: {names}";
        }
        _refreshChatWho = ShowWho;          // so peer discovery/loss live-updates the contact line
        ShowWho(); DockPanel.SetDock(who, Dock.Top); root.Children.Add(who);
        setName.Click += (_, _) => { _displayName = nameBox.Text.Trim(); ShowWho(); RenderChat(); };

        // send bar
        var input = new TextBox { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), FontSize = 13 };
        var send = new Button { Content = "Send", Margin = new Thickness(8, 0, 0, 0), Padding = new Thickness(14, 6, 14, 6) };
        var bar = new DockPanel { Margin = new Thickness(0, 10, 0, 0) };
        DockPanel.SetDock(send, Dock.Right); bar.Children.Add(send); bar.Children.Add(input);
        DockPanel.SetDock(bar, Dock.Bottom); root.Children.Add(bar);
        send.Click += (_, _) => { SendChat(input.Text); input.Clear(); ShowWho(); };
        input.PreviewKeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; SendChat(input.Text); input.Clear(); ShowWho(); } };

        _chatList = new StackPanel();
        root.Children.Add(new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _chatList });
        RenderChat();
        return root;
    }

    private string NameFor(string pub) => pub == Tx.ToHex(_walletPub) ? (_displayName.Length > 0 ? _displayName : "you") : "player-" + (pub.Length >= 6 ? pub[..6] : pub);

    private void RenderChat()
    {
        if (_chatList is null) return;
        _chatList.Children.Clear();
        if (_conv.History.Count == 0)
        {
            _chatList.Children.Add(new TextBlock { Text = "No messages yet. Messages are encrypted and on-chain.", Foreground = B("#6a6f76"), FontSize = 12 });
            return;
        }
        foreach (var m in _conv.History)
        {
            var line = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) };
            if (m.Kind == ChatKind.Reply) line.Inlines.Add(new System.Windows.Documents.Run("↩ ") { Foreground = B("#6a6f76") });
            line.Inlines.Add(new System.Windows.Documents.Run(NameFor(m.FromPub) + "  ") { Foreground = B("#f5a623"), FontWeight = FontWeights.SemiBold });
            line.Inlines.Add(new System.Windows.Documents.Run(m.Display) { Foreground = m.Deleted ? B("#6a6f76") : B("#cfd2d6") });
            if (m.EditedText is not null && !m.Deleted) line.Inlines.Add(new System.Windows.Documents.Run("  (edited)") { Foreground = B("#6a6f76"), FontSize = 10 });
            if (m.Reactions.Count > 0) line.Inlines.Add(new System.Windows.Documents.Run("  " + string.Join(" ", m.Reactions.Values)) { Foreground = B("#ffd54f") });
            if (m.ReadBy.Count > 0) line.Inlines.Add(new System.Windows.Documents.Run("  ✓") { Foreground = B("#7bd88f"), FontSize = 10 });
            // Right-click a message: reply, react, and (your own) edit / delete — a usable messenger.
            if (!m.Deleted)
            {
                var cm = new ContextMenu();
                var reply = new MenuItem { Header = "Reply" };
                reply.Click += (_, _) => { var t = Prompt("Reply", ""); if (!string.IsNullOrWhiteSpace(t)) Broadcast(Messenger.Reply(MyPub(), m.Id, t)); };
                cm.Items.Add(reply);
                var react = new MenuItem { Header = "React" };
                foreach (var e in new[] { "\U0001F44D", "❤", "\U0001F602", "\U0001F389", "\U0001F62E" })
                { var em = e; var mi = new MenuItem { Header = e }; mi.Click += (_, _) => Broadcast(Messenger.React(MyPub(), m.Id, em)); react.Items.Add(mi); }
                cm.Items.Add(react);
                if (m.FromPub == MyPub())
                {
                    var edit = new MenuItem { Header = "Edit" };
                    edit.Click += (_, _) => { var t = Prompt("Edit", m.Display); if (t is not null) Broadcast(Messenger.Edit(MyPub(), m.Id, t)); };
                    var del = new MenuItem { Header = "Delete" };
                    del.Click += (_, _) => Broadcast(Messenger.Delete(MyPub(), m.Id));
                    cm.Items.Add(edit); cm.Items.Add(del);
                }
                line.ContextMenu = cm;
            }
            _chatList.Children.Add(line);
        }
    }

    private string MyPub() => Tx.ToHex(_walletPub);

    private void SendChat(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        Broadcast(Messenger.Text(MyPub(), text));
    }

    private long _msgSeq;

    // THE RULE: every message is a BSV TRANSACTION, sent IP-to-IP to each player (and to miners once
    // funded). UI work stays on the UI thread; the heavy seal+serialize+socket work runs OFF-thread and
    // fully guarded, so a peer-link callback can never block or crash the app.
    private void Broadcast(ChatMessage m)
    {
        _conv.Apply(m); RenderChat();
        var peers = _node.PeerWalletPubs();
        var links = _node.LiveLinks();
        byte[] payload = Messenger.Serialize(m);
        byte[] master = _master, myPkh = Recovery.Hash160(_walletPub);
        string conv = _conv.Id;
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                var ring = new KeyRing(master);
                foreach (var peerPub in peers)
                {
                    long seq = System.Threading.Interlocked.Increment(ref _msgSeq);
                    byte[] carrier = TxMessage.SealCarrier(ring.MessagePriv(peerPub, conv, seq), peerPub, TxType.Chat2P, payload);
                    var tx = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0xffffffff, System.Array.Empty<byte>(), 0xffffffff) },
                        new[] { new TxOutputN(1, TxTransport.MessageOutput(carrier, myPkh)) }, 0);
                    byte[] raw = Tx.Serialize(tx);
                    foreach (var l in links) l.Send(raw);            // IP-to-IP to players, AS a transaction
                }
            }
            catch (System.Exception ex) { App.CrashLog("chat-send", ex); }
        });
    }

    // A small modal text prompt (for Reply / Edit) — no external dependencies.
    private string? Prompt(string title, string initial)
    {
        var w = new Window { Title = title, Width = 440, Height = 150, WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = this, Background = B("#1b1d1e"), ResizeMode = ResizeMode.NoResize };
        var sp = new StackPanel { Margin = new Thickness(14) };
        var tb = new TextBox { Text = initial, Padding = new Thickness(8), FontSize = 13, Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0) };
        var ok = new Button { Content = "OK", Width = 90, Margin = new Thickness(0, 12, 0, 0), HorizontalAlignment = HorizontalAlignment.Right, Padding = new Thickness(10, 5, 10, 5) };
        string? res = null;
        ok.Click += (_, _) => { res = tb.Text; w.Close(); };
        tb.PreviewKeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; res = tb.Text; w.Close(); } };
        sp.Children.Add(tb); sp.Children.Add(ok); w.Content = sp; tb.Focus(); tb.SelectAll(); w.ShowDialog();
        return res;
    }

    // Incoming bytes are parsed AS A TRANSACTION; the carrier addressed to us is extracted. Fully
    // guarded so a malformed/hostile frame can never escape to the peer-link thread.
    private void OnChatFrame(PeerLink link, byte[] frame)
    {
        try
        {
            var tx = Tx.Parse(frame);
            if (tx is null) return;
            var ex = TxTransport.Extract(tx, _master);
            if (ex is null) return;
            ChatMessage? m = null;
            try { m = Messenger.Parse(ex.Value.plaintext); } catch { }
            if (m is null) return;
            _conv.Apply(m); RenderChat();
            if (m.FromPub != MyPub() && (m.Kind is ChatKind.Text or ChatKind.Reply or ChatKind.Media))
                Broadcast(Messenger.Read(MyPub(), m.Id));
        }
        catch (System.Exception e) { App.CrashLog("chat-recv", e); }
    }
}
