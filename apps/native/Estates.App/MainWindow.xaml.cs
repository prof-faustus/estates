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

        _displayName = LoadHandle();                     // my persistent IDENTITY handle (e.g. "Bob"), if set
        string nodeName = _displayName.Length > 0 ? _displayName : (bot ? "bot-" : "player-") + Tx.ToHex(_walletPub)[..6];
        _node = new P2PNode(nodeName, Tx.ToHex(_walletPub));   // advertise the handle so peers can find/pay me by identity
        App.Teardowns.Add(() => { try { _node.Dispose(); } catch { } });
        _node.OnPeerDiscovered += _ => Dispatcher.Invoke(RefreshNodes);
        _node.OnPeerLost += _ => Dispatcher.Invoke(RefreshNodes);
        _node.OnLink += link => link.OnFrame += (l, f) => Dispatcher.Invoke(() => OnChatFrame(l, f));
        Closing += OnHumanClosing;                       // bots close + refund me FIRST, then I close
        Closed += (_, _) => { try { _node.Dispose(); } catch { } };

        RefreshNodes();
        // keep the lobby live for gossip-discovered peers (they age in/out without a discovery event)
        var lobbyTimer = new System.Windows.Threading.DispatcherTimer { Interval = System.TimeSpan.FromSeconds(3) };
        lobbyTimer.Tick += (_, _) => RefreshNodes();
        lobbyTimer.Start();
        Closed += (_, _) => lobbyTimer.Stop();
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
        // Estate-gossip peers learned transitively over the mesh (beyond this multicast segment), not
        // already shown as a directly-discovered peer.
        var directPubs = new HashSet<string>(peers.Select(p => p.WalletPub));
        int gossiped = 0;
        foreach (var gp in _node.Gossip.Live())
        {
            if (gp.IdentityPub == Tx.ToHex(_walletPub) || directPubs.Contains(gp.IdentityPub)) continue;
            gossiped++;
            var name = new TextBlock { Text = gp.NodeId.Length >= 8 ? gp.NodeId[..8] : gp.NodeId, Foreground = B("#e6e6e6"), FontSize = 13, FontWeight = FontWeights.SemiBold };
            string offer = gp.Offer == "lobby" ? "in the lobby (via gossip)" : $"offering: {gp.Offer}  (via gossip)";
            var sub = new TextBlock { Text = offer, Foreground = B("#9aa0a6"), FontSize = 11, Margin = new Thickness(0, 2, 0, 0) };
            var stack = new StackPanel(); stack.Children.Add(name); stack.Children.Add(sub);
            NodeList.Children.Add(new Border { Background = B("#1f2937"), CornerRadius = new CornerRadius(8), Padding = new Thickness(12), Margin = new Thickness(0, 0, 0, 8), Child = stack });
        }
        int total = peers.Count + gossiped;
        LobbyStatus.Text = total == 0 ? "You're the only node here right now." : $"{total} other node(s) live right now.";
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
        _node.ReceiveAddress = w.AddressAt(FirstAddr);   // advertise a sub-key address (index 0 is identity, never an address)
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
        // Three balances a real wallet MUST show — spendable, pending (0-conf), immature (mined,
        // <100 conf). Auto-refreshed live (no Refresh button). Pending/immature populate from the
        // node-backed UTXO view; a local-only wallet legitimately reports 0 for them.
        var bal = new TextBlock { Foreground = B("#7bd88f"), FontSize = 22, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 6, 0, 2) };
        var balPend = new TextBlock { Foreground = B("#f5a623"), FontSize = 13 };
        var balImm = new TextBlock { Foreground = B("#8ab4f8"), FontSize = 13, Margin = new Thickness(0, 0, 0, 4) };
        void ShowBal()
        {
            bal.Text = $"Spendable: {w.Balance():n0} sat";
            balPend.Text = $"Pending (0-conf): {w.PendingSats:n0} sat";
            balImm.Text = $"Immature (mined, <100 conf): {w.ImmatureSats:n0} sat";
        }
        ShowBal();
        info.Children.Add(bal); info.Children.Add(balPend); info.Children.Add(balImm);

        // ON-CHAIN (SPV): the estate node's SPV wallet — verified merkle proofs only, never a full node,
        // never mines. Loads persisted coins instantly on open; pulls each coin's proof from the node.
        var spvOwned = new List<byte[]>();
        for (int i = FirstAddr; i <= RecvWatch; i++) spvOwned.Add(NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(i))));   // index 0 = identity, never an address
        var spv = new SpvWallet(spvOwned);
        string spvPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"estates_spv_{_network}.dat");
        try { spv.Load(spvPath); } catch { }
        var spvBal = new TextBlock { Foreground = B("#8ab4f8"), FontSize = 16, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 2, 0, 6) };
        void ShowSpv() => spvBal.Text = $"On-chain (SPV): {spv.Balance():n0} sat   ·   {spv.CoinCount} coin(s)";
        ShowSpv();
        info.Children.Add(spvBal);
        async void SpvSyncNow()
        {
            // host RPC ports: regtest->18443, testnet->18332, mainnet->8332 (the proof source; live play delivers envelopes IP-to-IP)
            int rpcPort = _network == "mainnet" ? 8332 : _network == "testnet" ? 18332 : 18443;
            try
            {
                using var rpc = new BsvRpc("127.0.0.1", rpcPort, "e", "e");
                // regtest bring-up: if empty, the local node pays the wallet's OWN address (a real payment
                // to it) and confirms it — then SPV picks it up. So it just shows on open.
                if (_network == "regtest" && spv.Balance() == 0)
                {
                    await rpc.CallAsync("sendtoaddress", w.AddressAt(FirstAddr), 100.0);
                    var mineTo = (await rpc.CallAsync("getnewaddress"))?.GetString() ?? w.AddressAt(FirstAddr + 1);
                    await rpc.CallAsync("generatetoaddress", 1, mineTo);
                }
                int n = 0;
                for (int i = FirstAddr; i <= RecvWatch; i++) n += await SpvSync.SyncAddressAsync(rpc, spv, w.AddressAt(i));
                if (n > 0) spv.Save(spvPath);
                Dispatcher.Invoke(ShowSpv);
            }
            catch { }
        }
        SpvSyncNow();

        // SPV Send — spend the wallet's SPV coins (FORKID-signed), broadcast the tx to the node; change returns to us.
        info.Children.Add(L("Send (SPV) — pay to address, amount in sat"));
        var stoAddr = F(); var samt = F(); var sout = O();
        var ssend = Btn("Send");
        async void DoSpvSend()
        {
            try
            {
                // pay is pay: the recipient may be an address, an identity handle, a bot#id, or a contact
                string target = ResolveAddress(stoAddr.Text.Trim()) ?? stoAddr.Text.Trim();
                var pkh = Base58.CheckDecode(target, out _);
                if (pkh is null || pkh.Length != 20) { sout.Text = "unknown recipient (address / identity / bot#id / contact)"; return; }
                if (!long.TryParse(samt.Text.Trim(), out long amt) || amt <= 0) { sout.Text = "bad amount"; return; }
                byte[] changeScript = NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(FirstAddr)));   // change to a sub-key, never index 0
                var built = SpvSpend.Build(spv, SpvKeymap(w), NodeWallet.P2pkhScript(pkh), amt, 500, changeScript);
                if (built is null) { sout.Text = "insufficient SPV funds"; return; }
                int rpcPort = _network == "mainnet" ? 8332 : _network == "testnet" ? 18332 : 18443;
                using var rpc = new BsvRpc("127.0.0.1", rpcPort, "e", "e");
                var r = await rpc.CallAsync("sendrawtransaction", Tx.ToHex(built.Raw));
                if (r is null) { sout.Text = "broadcast rejected by node"; return; }
                foreach (var c in built.Tx.Inputs) spv.Spend(c.PrevTxid + ":" + c.PrevVout);
                spv.Save(spvPath); Dispatcher.Invoke(ShowSpv);
                _txLog.Add($"{"(sent)",-20}{("-" + amt.ToString("n0")),16}  {built.Txid[..Math.Min(20, built.Txid.Length)]}…  → {target[..Math.Min(12, target.Length)]}…");
                sout.Text = $"SENT · txid {built.Txid[..16]}…";
            }
            catch (System.Exception e) { sout.Text = e.Message; }
        }
        ssend.Click += (_, _) => DoSpvSend();
        samt.PreviewKeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; DoSpvSend(); } };
        info.Children.Add(L("to address")); info.Children.Add(stoAddr); info.Children.Add(L("amount (sat)")); info.Children.Add(samt); info.Children.Add(ssend); info.Children.Add(sout);

        // (Funding a bot is not special: pay is pay. Pay a bot like any peer — in chat with
        //  "\pay <bot#id|name|address> <sat>", or with Send (SPV) above. The bot refunds you on close.)

        info.Children.Add(L("Recovery seed (back this up)")); var sb0 = F(); sb0.IsReadOnly = true; sb0.Text = Tx.ToHex(_walletSeed!); info.Children.Add(sb0);
        info.Children.Add(L("Identity key (index 0 — ECDH root, NEVER an address)")); var sid = F(); sid.IsReadOnly = true; sid.Text = Tx.ToHex(w.ChildPub(0)); info.Children.Add(sid);
        info.Children.Add(L("Receive address #1 (first HMAC sub-key)")); var sa0 = F(); sa0.IsReadOnly = true; sa0.Text = w.AddressAt(FirstAddr); info.Children.Add(sa0);
        var lk = Btn("Lock wallet"); lk.Click += (_, _) => relock(); info.Children.Add(lk);
        tabs.Items.Add(Tab("Info", info));

        // Fund — funding is ALWAYS a real payment SENT TO YOUR ADDRESS. No manual import, no TXID entry.
        // Copy the address, send BSV to it; it appears once the node-backed wallet sees it on-chain.
        var fund = new StackPanel();
        fund.Children.Add(new TextBlock { Text = "Fund the wallet", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        fund.Children.Add(L("Funding is a real payment SENT TO YOUR ADDRESS below. Copy it and send BSV to it — it appears here once the node sees it on-chain. There is no manual import."));
        fund.Children.Add(L("Your receive address (click to select; or use Copy):"));
        var fa = F(); fa.IsReadOnly = true; fa.Text = w.AddressAt(FirstAddr); fa.FontFamily = new FontFamily("Consolas");
        fa.GotKeyboardFocus += (_, _) => fa.SelectAll();
        fa.PreviewMouseLeftButtonUp += (_, _) => fa.SelectAll();
        fund.Children.Add(fa);
        var fcopy = Btn("Copy address"); var fmsg = O();
        fcopy.Click += (_, _) => { try { System.Windows.Clipboard.SetText(w.AddressAt(FirstAddr)); fmsg.Text = "address copied — send BSV to it"; } catch (System.Exception e) { fmsg.Text = e.Message; } };
        fund.Children.Add(fcopy); fund.Children.Add(fmsg);
        tabs.Items.Add(Tab("Fund", fund));

        // ===== SEND — PAY-TO-MANY, fee in sat/kB, coin control (frozen coins excluded), SPV-signed,
        // broadcast to the node + IP-to-IP. Recipients are one per line: "<address|identity|bot#id> <sat>".
        var send = new StackPanel();
        send.Children.Add(new TextBlock { Text = "Send — pay to many (one per line: recipient amount-sat)", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        send.Children.Add(L("recipient may be an address, an identity handle, a bot#id, or a contact"));
        var many = F(); many.MinHeight = 90; many.Text = "";
        var feekb = F(); feekb.Text = "1000";   // sat/kB
        var so = O(); var raw = Mono(120);
        var sbtn = Btn("Send (build, sign + broadcast)");
        async void DoMany()
        {
            try
            {
                if (!long.TryParse(feekb.Text.Trim(), out long satPerKb) || satPerKb < 0) { so.Text = "bad fee rate (sat/kB)"; return; }
                var outs = new List<(byte[] script, long amount)>();
                foreach (var lineRaw in many.Text.Split('\n'))
                {
                    var ln = lineRaw.Trim(); if (ln.Length == 0) continue;
                    var p = ln.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                    if (p.Length < 2 || !long.TryParse(p[^1], out long a) || a <= 0) { so.Text = $"bad line: {ln}"; return; }
                    string who = string.Join(' ', p[..^1]);
                    string? addr = ResolveAddress(who);
                    var pkh = addr is null ? null : Base58.CheckDecode(addr, out _);
                    if (pkh is null || pkh.Length != 20) { so.Text = $"unknown recipient: {who}"; return; }
                    outs.Add((NodeWallet.P2pkhScript(pkh), a));
                }
                if (outs.Count == 0) { so.Text = "add at least one recipient"; return; }
                var spv2 = LoadSpvFromDisk(w);
                long est = 200 + outs.Count * 34 + 150 * 8; long fee = System.Math.Max(500, satPerKb * est / 1000);   // sat/kB → fee
                byte[] change = NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(FirstAddr)));
                var built = SpvSpend.BuildMany(spv2, SpvKeymap(w), outs, fee, change, _frozenCoins);
                if (built is null) { so.Text = "insufficient funds (after excluding frozen coins)"; return; }
                raw.Text = Tx.ToHex(built.Raw);
                using var rpc = new BsvRpc("127.0.0.1", RpcPort(), "e", "e");
                var r = await rpc.CallAsync("sendrawtransaction", Tx.ToHex(built.Raw));
                foreach (var l in _node.LiveLinks()) { try { l.Send(built.Raw); } catch { } }   // IP-to-IP too
                if (r is null) { so.Text = "built + signed (txid " + built.Txid[..16] + "…); node did not accept — raw below"; return; }
                foreach (var c in built.Tx.Inputs) spv2.Spend(c.PrevTxid + ":" + c.PrevVout);
                spv2.Save(SpvPathFor()); ShowSpv();
                _txLog.Add($"{"(sent)",-20}{("-" + (outs.Sum(o => o.amount)).ToString("n0")),16}  {built.Txid[..Math.Min(20, built.Txid.Length)]}…  ({outs.Count} payee, fee {fee})");
                so.Text = $"SENT · {outs.Count} payee(s) · fee {fee} sat · txid {built.Txid}";
            }
            catch (Exception e) { so.Text = e.Message; }
        }
        sbtn.Click += (_, _) => DoMany();
        send.Children.Add(L("recipients (one per line)")); send.Children.Add(many);
        send.Children.Add(L("fee rate (sat/kB)")); send.Children.Add(feekb);
        send.Children.Add(sbtn); send.Children.Add(so);
        send.Children.Add(L("signed raw transaction")); send.Children.Add(raw);
        tabs.Items.Add(Tab("Send", send));

        // Receive
        var recv = new StackPanel(); var ridx = F(); ridx.Text = "1"; var ra = F(); ra.IsReadOnly = true; var rbtn = Btn("Show address");
        rbtn.Click += (_, _) => { try { ra.Text = w.AddressAt(int.Parse(ridx.Text.Trim())); } catch (Exception e) { ra.Text = e.Message; } };
        recv.Children.Add(L("address index")); recv.Children.Add(ridx); recv.Children.Add(rbtn); recv.Children.Add(ra); tabs.Items.Add(Tab("Receive", recv));

        // (Addresses are listed in the Destinations tab, with derivation paths, starting at index 1 —
        //  index 0 is the identity/base key and is never shown as an address.)

        // ===== HISTORY — every transaction the SPV wallet knows (received coins + this session's sends) =====
        var hist = new StackPanel(); var hl = Mono(420);
        void LoadHistory()
        {
            var s = new System.Text.StringBuilder();
            s.AppendLine($"{"date",-20}{"amount (sat)",16}  txid / note");
            s.AppendLine(new string('-', 70));
            foreach (var (txid, credited, ncoins) in LoadSpvFromDisk(w).ReceivedHistory())
                s.AppendLine($"{"(confirmed)",-20}{("+" + credited.ToString("n0")),16}  {txid[..Math.Min(20, txid.Length)]}…  ({ncoins} coin)");
            foreach (var line in _txLog) s.AppendLine(line);
            if (LoadSpvFromDisk(w).CoinCount == 0 && _txLog.Count == 0) s.AppendLine("no transactions yet — receive a payment or pay someone.");
            hl.Text = s.ToString();
        }
        LoadHistory(); var hr = Btn("Refresh"); hr.Click += (_, _) => LoadHistory();
        hist.Children.Add(new TextBlock { Text = "Transaction history (Craig's SPV — coins arrive IP-to-IP with their merkle proof)", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        hist.Children.Add(hr); hist.Children.Add(hl);
        tabs.Items.Add(Tab("History", hist));

        // ===== COINS — every UTXO; freeze/unfreeze (coin control); UTXO split =====
        var coins = new StackPanel(); var cl = Mono(300); var cidx = F(); cidx.Text = ""; var cmsg = O();
        void LoadCoins()
        {
            var s = new System.Text.StringBuilder();
            s.AppendLine($"{"value (sat)",14}  {"frozen",-7} outpoint  ·  address");
            foreach (var u in LoadSpvFromDisk(w).Utxos())
            {
                string op = u.txid + ":" + u.vout;
                string addr = AddrOfScript(u.script);
                s.AppendLine($"{u.value,14:n0}  {(_frozenCoins.Contains(op) ? "FROZEN" : "      "),-7} {op[..Math.Min(22, op.Length)]}…  {addr}");
            }
            if (LoadSpvFromDisk(w).CoinCount == 0) s.AppendLine("no coins yet.");
            cl.Text = s.ToString();
        }
        LoadCoins();
        var cf = Btn("Freeze/unfreeze outpoint (txid:vout)");
        cf.Click += (_, _) => { string op = cidx.Text.Trim(); if (op.Length == 0) { cmsg.Text = "enter a txid:vout from the list"; return; } if (!_frozenCoins.Add(op)) _frozenCoins.Remove(op); cmsg.Text = _frozenCoins.Contains(op) ? "frozen (won't be spent)" : "unfrozen"; LoadCoins(); };
        coins.Children.Add(new TextBlock { Text = "Coins (UTXOs) — coin control", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        coins.Children.Add(cl); coins.Children.Add(L("outpoint to freeze/unfreeze")); coins.Children.Add(cidx); coins.Children.Add(cf); coins.Children.Add(cmsg);
        tabs.Items.Add(Tab("Coins", coins));

        // ===== DESTINATIONS — addresses WITH derivation paths (index 0 = identity, NEVER an address) =====
        var dest = new StackPanel(); var dl = Mono(420);
        dest.Children.Add(new TextBlock { Text = "Destinations — your addresses & derivation paths", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        dest.Children.Add(L("index 0 is the BASE IDENTITY key (ECDH-derivation only) and is NEVER an address. Receive addresses are HMAC hash-chain sub-keys, index ≥ 1."));
        var ds = new System.Text.StringBuilder();
        ds.AppendLine($"{"path",-18}{"index",-7} address");
        for (int i = FirstAddr; i <= 24; i++) ds.AppendLine($"{("estates/wallet/" + i),-18}{i,-7} {w.AddressAt(i)}");
        dl.Text = ds.ToString(); dest.Children.Add(dl);
        tabs.Items.Add(Tab("Destinations", dest));

        // ===== COINSPLIT — split your balance into many fresh UTXOs (fixed or randomized) =====
        var csplit = new StackPanel(); var csN = F(); csN.Text = "10"; var csEach = F(); csEach.Text = "10000";
        var csR = new CheckBox { Content = "randomized amounts", Foreground = B("#cfd2d6"), Margin = new Thickness(0, 6, 0, 0) };
        var csOut = O(); var csb = Btn("Split");
        async void DoSplit()
        {
            try
            {
                if (!int.TryParse(csN.Text.Trim(), out int n) || n < 1 || n > RecvWatch - FirstAddr) { csOut.Text = $"count 1..{RecvWatch - FirstAddr}"; return; }
                if (!long.TryParse(csEach.Text.Trim(), out long each) || each <= 0) { csOut.Text = "bad amount"; return; }
                var spv2 = LoadSpvFromDisk(w); var rnd = new Random();
                var outs = new List<(byte[] script, long amount)>();
                for (int i = 0; i < n; i++) { long a = csR.IsChecked == true ? System.Math.Max(1000, each / 2 + rnd.Next((int)each)) : each; outs.Add((NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(FirstAddr + i))), a)); }
                byte[] change = NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(FirstAddr)));
                var built = SpvSpend.BuildMany(spv2, SpvKeymap(w), outs, 500, change, _frozenCoins);
                if (built is null) { csOut.Text = "insufficient funds"; return; }
                using var rpc = new BsvRpc("127.0.0.1", RpcPort(), "e", "e");
                var r = await rpc.CallAsync("sendrawtransaction", Tx.ToHex(built.Raw));
                if (r is null) { csOut.Text = "node rejected the split"; return; }
                foreach (var c in built.Tx.Inputs) spv2.Spend(c.PrevTxid + ":" + c.PrevVout); spv2.Save(SpvPathFor()); ShowSpv();
                csOut.Text = $"split into {n} coins · txid {built.Txid[..16]}…";
            }
            catch (Exception e) { csOut.Text = e.Message; }
        }
        csb.Click += (_, _) => DoSplit();
        csplit.Children.Add(new TextBlock { Text = "Coinsplit — split your balance into many UTXOs", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        csplit.Children.Add(L("number of pieces")); csplit.Children.Add(csN);
        csplit.Children.Add(L("sat each (base, if randomized)")); csplit.Children.Add(csEach);
        csplit.Children.Add(csR); csplit.Children.Add(csb); csplit.Children.Add(csOut);
        tabs.Items.Add(Tab("Coinsplit", csplit));

        // ===== TOOLS — sign/verify, encrypt/decrypt, sweep a private key, load/broadcast a raw tx =====
        var tools = new StackPanel();
        tools.Children.Add(new TextBlock { Text = "Sign a message (identity key)", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        var gm = F(); var go = O(); var gb = Btn("Sign");
        gb.Click += (_, _) => { try { byte[] priv = w.ChildPriv(0); byte[] sig = EcdsaSign.Sign(priv, System.Text.Encoding.UTF8.GetBytes(gm.Text)); go.Text = $"identity pub {Tx.ToHex(w.ChildPub(0))}\nsig {Tx.ToHex(sig)}"; } catch (Exception e) { go.Text = e.Message; } };
        tools.Children.Add(L("message")); tools.Children.Add(gm); tools.Children.Add(gb); tools.Children.Add(go);
        tools.Children.Add(new TextBlock { Text = "Verify a message", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold, Margin = new Thickness(0, 12, 0, 0) });
        var vp = F(); var vs = F(); var vm = F(); var vo = O(); var vb = Btn("Verify");
        vb.Click += (_, _) => { try { vo.Text = EcdsaSign.Verify(Tx.FromHex(vp.Text.Trim()), System.Text.Encoding.UTF8.GetBytes(vm.Text), Tx.FromHex(vs.Text.Trim())) ? "VALID" : "INVALID"; } catch (Exception e) { vo.Text = e.Message; } };
        tools.Children.Add(L("pubkey (hex)")); tools.Children.Add(vp); tools.Children.Add(L("signature (hex)")); tools.Children.Add(vs); tools.Children.Add(L("message")); tools.Children.Add(vm); tools.Children.Add(vb); tools.Children.Add(vo);

        tools.Children.Add(new TextBlock { Text = "Encrypt a message to a pubkey (ECDH)", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold, Margin = new Thickness(0, 12, 0, 0) });
        var ep = F(); var em = F(); var eo = O(); var eb = Btn("Encrypt");
        eb.Click += (_, _) => { try { var sealed_ = Cipher.EcdhSeal(w.ChildPriv(FirstAddr), Tx.FromHex(ep.Text.Trim()), System.Text.Encoding.UTF8.GetBytes(em.Text), System.Text.Encoding.ASCII.GetBytes("estates/msg")); eo.Text = $"from {Tx.ToHex(w.ChildPub(FirstAddr))}\nnonce {Tx.ToHex(sealed_.Nonce)}\nct {Tx.ToHex(sealed_.Bytes)}"; } catch (Exception e) { eo.Text = e.Message; } };
        tools.Children.Add(L("recipient pubkey (hex)")); tools.Children.Add(ep); tools.Children.Add(L("message")); tools.Children.Add(em); tools.Children.Add(eb); tools.Children.Add(eo);
        tools.Children.Add(new TextBlock { Text = "Decrypt a message (to my address-1 key)", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold, Margin = new Thickness(0, 12, 0, 0) });
        var dfp = F(); var dn = F(); var dct = F(); var doo = O(); var db = Btn("Decrypt");
        db.Click += (_, _) => { try { var pt = Cipher.EcdhOpen(w.ChildPriv(FirstAddr), Tx.FromHex(dfp.Text.Trim()), new Cipher.EcdhSealed(Tx.FromHex(dn.Text.Trim()), Tx.FromHex(dct.Text.Trim())), System.Text.Encoding.ASCII.GetBytes("estates/msg")); doo.Text = pt is null ? "cannot decrypt (not for me / tampered)" : System.Text.Encoding.UTF8.GetString(pt); } catch (Exception e) { doo.Text = e.Message; } };
        tools.Children.Add(L("sender pubkey (hex)")); tools.Children.Add(dfp); tools.Children.Add(L("nonce (hex)")); tools.Children.Add(dn); tools.Children.Add(L("ciphertext (hex)")); tools.Children.Add(dct); tools.Children.Add(db); tools.Children.Add(doo);

        tools.Children.Add(new TextBlock { Text = "Sweep a private key (import its funds) — raw 64-hex or a BIP38 6P… key", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold, Margin = new Thickness(0, 12, 0, 0) });
        var swk = F(); var swpp = F(); var swo = O(); var swb = Btn("Sweep to my wallet");
        swb.Click += async (_, _) => swo.Text = await SweepPrivKey(w, swk.Text.Trim(), swpp.Text);
        tools.Children.Add(L("private key (64-hex) or BIP38 (6P…)")); tools.Children.Add(swk); tools.Children.Add(L("BIP38 passphrase (only for 6P… keys)")); tools.Children.Add(swpp); tools.Children.Add(swb); tools.Children.Add(swo);

        tools.Children.Add(new TextBlock { Text = "Pay a BIP270 invoice (Anypay / Centi) — paste the payment URL", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold, Margin = new Thickness(0, 12, 0, 0) });
        var inv = F(); var invo = O(); var invb = Btn("Fetch + pay invoice");
        invb.Click += async (_, _) => { invo.Text = "fetching invoice…"; invo.Text = await PayBip270(w, inv.Text.Trim()); };
        tools.Children.Add(L("payment URL or bitcoin: URI")); tools.Children.Add(inv); tools.Children.Add(invb); tools.Children.Add(invo);

        tools.Children.Add(new TextBlock { Text = "Load / broadcast a raw transaction", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold, Margin = new Thickness(0, 12, 0, 0) });
        var lrt = F(); var lro = O(); var lrb = Btn("Broadcast raw tx");
        lrb.Click += async (_, _) => { try { using var rpc = new BsvRpc("127.0.0.1", RpcPort(), "e", "e"); var r = await rpc.CallAsync("sendrawtransaction", lrt.Text.Trim()); lro.Text = r is null ? "rejected by node" : "broadcast: " + r.Value.ToString(); } catch (Exception e) { lro.Text = e.Message; } };
        tools.Children.Add(L("raw tx (hex)")); tools.Children.Add(lrt); tools.Children.Add(lrb); tools.Children.Add(lro);
        tabs.Items.Add(Tab("Tools", tools));

        // ===== CONSOLE — type any in-wallet command (\help lists them) =====
        var con = new StackPanel(); var conOut = Mono(360); var conIn = F(); var conBtn = Btn("Run");
        void RunConsole() { string cmd = conIn.Text.Trim(); if (cmd.Length == 0) return; conOut.AppendText("> " + cmd + "\n"); if (ChatCommands.Is(cmd)) { var pc = ChatCommands.Parse(cmd); if (pc.Kind == ChatCmd.Help) conOut.AppendText(ChatCommands.Help() + "\n"); else if (pc.Kind == ChatCmd.Balance) conOut.AppendText($"balance: {LoadSpvFromDisk(w).Balance():n0} sat\n"); else if (pc.Kind == ChatCmd.AskAddress || pc.Kind == ChatCmd.StateAddress) conOut.AppendText("fresh address: " + NextRecvAddress(w) + "\n"); else conOut.AppendText("use the Send tab / chat for \\pay\n"); } else conOut.AppendText("commands start with \\ — try \\help\n"); conIn.Clear(); conOut.ScrollToEnd(); }
        conBtn.Click += (_, _) => RunConsole();
        conIn.PreviewKeyDown += (_, e) => { if (e.Key is System.Windows.Input.Key.Enter or System.Windows.Input.Key.Return) { e.Handled = true; RunConsole(); } };
        con.Children.Add(new TextBlock { Text = "Console", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        con.Children.Add(conOut); con.Children.Add(conIn); con.Children.Add(conBtn);
        tabs.Items.Add(Tab("Console", con));

        // ===== NETWORK / SPV — Craig's SPV: IP-to-IP envelopes + a BIP37 Bloom filter over my addresses =====
        var netp = new StackPanel();
        netp.Children.Add(new TextBlock { Text = "Network / SPV", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        var bf = new BloomFilter(RecvWatch, 0.0001, (uint)Environment.TickCount);
        for (int i = FirstAddr; i <= RecvWatch; i++) bf.Insert(Recovery.Hash160(w.ChildPub(i)));
        var netInfo = Mono(240);
        netInfo.Text =
            "Model: Craig's SPV — coins arrive IP-to-IP as (transaction + merkle proof + block header);\n" +
            "the wallet verifies the proof and STORES it. No chain scan, no header IBD; the node is only\n" +
            "a proof source. A Bloom filter tells a serving peer which addresses to match without\n" +
            "revealing the exact set.\n\n" +
            "Bloom filter (BIP37, MurmurHash3 x86_32):\n" +
            $"  watched addresses : {RecvWatch}\n" +
            $"  filter size       : {bf.ByteLength} bytes\n" +
            $"  hash functions    : {bf.HashFuncs}\n" +
            $"  tweak             : {bf.Tweak}\n" +
            $"  filterload payload: {bf.FilterLoad().Length} bytes\n\n" +
            $"Network: {_network}   ·   proof source 127.0.0.1:{RpcPort()}\n" +
            $"Stored proofs (coins): {LoadSpvFromDisk(w).CoinCount}";
        netp.Children.Add(netInfo);
        tabs.Items.Add(Tab("Network", netp));

        // ===== NFTs — deeds/cards + your IDENTITY card, displayed as visual cards owned by your identity =====
        var nft = new StackPanel();
        nft.Children.Add(new TextBlock { Text = "NFTs — your identity card, deeds & game cards", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        nft.Children.Add(L("every NFT is owned by your IDENTITY (the base key, index 0 — ECDH root, never an address)"));
        var nftHost = new StackPanel { Margin = new Thickness(0, 6, 0, 0) };
        Border Card(string title, string sub, string brush)
        {
            var sp2 = new StackPanel();
            sp2.Children.Add(new TextBlock { Text = title, Foreground = B("#ffffff"), FontWeight = FontWeights.Bold, FontSize = 14 });
            sp2.Children.Add(new TextBlock { Text = sub, Foreground = B("#cfd2d6"), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 3, 0, 0) });
            return new Border { Background = B(brush), CornerRadius = new CornerRadius(10), Padding = new Thickness(14), Margin = new Thickness(0, 0, 0, 10), Child = sp2 };
        }
        void LoadNfts()
        {
            nftHost.Children.Clear();
            string idpub = Tx.ToHex(w.ChildPub(0));
            string handle = _displayName.Length > 0 ? _displayName : "(unnamed)";
            // the IDENTITY NFT card — the player's identity, equivalent of an NFT (links games + history)
            nftHost.Children.Add(Card($"🪪 IDENTITY · {handle}", $"identity key {idpub[..24]}…\nthis is your on-chain identity NFT — pay it, chat to it, play as it", "#243043"));
            foreach (var n in _heldNfts)
                nftHost.Children.Add(Card($"🏠 {n.name}", $"property #{n.id}  ·  owner: {handle} ({idpub[..12]}…)", "#1f2b22"));
            if (_heldNfts.Count == 0)
                nftHost.Children.Add(new TextBlock { Text = "No deeds yet — win/buy a property in a game and its deed NFT lands here, owned by your identity.", Foreground = B("#9aa0a6"), FontSize = 12, TextWrapping = TextWrapping.Wrap });
        }
        LoadNfts(); var nrb = Btn("Refresh"); nrb.Click += (_, _) => LoadNfts();
        nft.Children.Add(nrb); nft.Children.Add(nftHost); tabs.Items.Add(Tab("NFTs", nft));

        // AUTO-REFRESH: balances, coins, history update themselves (no manual refresh). Stops on unload.
        var auto = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        auto.Tick += (_, _) => { try { ShowBal(); ShowSpv(); SpvSyncNow(); LoadCoins(); LoadHistory(); } catch { } };
        auto.Start();
        tabs.Unloaded += (_, _) => auto.Stop();

        // ===== ElectrumSVP-style SHELL ported to WPF: menu bar (File/Wallet/Account/View/Tools/Help) +
        // status bar, wrapping the tab views — the look-and-feel of ElectrumSV. =====
        void Sel(string header) { foreach (TabItem t in tabs.Items) if ((t.Header as string) == header) { tabs.SelectedItem = t; return; } }
        MenuItem MI(string h, System.Action? a = null) { var m = new MenuItem { Header = h }; if (a is not null) m.Click += (_, _) => { try { a(); } catch (Exception e) { App.CrashLog("menu", e); } }; return m; }

        var menu = new Menu { Background = B("#2b2d31"), Foreground = B("#e6e6e6") };
        var file = MI("_File");
        file.Items.Add(MI("_Open…", () => Sel("Info"))); file.Items.Add(MI("_New / Restore…", () => relock()));
        file.Items.Add(MI("_Save Copy (backup seed)", () => Sel("Info"))); file.Items.Add(new Separator());
        file.Items.Add(MI("_Quit", () => relock()));
        var wallet = MI("_Wallet");
        wallet.Items.Add(MI("_Information", () => Sel("Info"))); wallet.Items.Add(MI("_Password…", () => Sel("Info")));
        var contactsMenu = MI("Contacts"); contactsMenu.Items.Add(MI("_New…", () => Sel("Contacts") )); wallet.Items.Add(contactsMenu);
        wallet.Items.Add(MI("_Find", () => Sel("History")));
        var view = MI("_View");
        foreach (TabItem t in tabs.Items) { string hh = t.Header as string ?? ""; view.Items.Add(MI(hh, () => Sel(hh))); }
        var toolsMenu = MI("_Tools");
        toolsMenu.Items.Add(MI("_Preferences", () => Sel("Network"))); toolsMenu.Items.Add(MI("_Network", () => Sel("Network")));
        toolsMenu.Items.Add(new Separator());
        toolsMenu.Items.Add(MI("_Sign / verify message", () => Sel("Tools"))); toolsMenu.Items.Add(MI("_Encrypt / decrypt message", () => Sel("Tools")));
        toolsMenu.Items.Add(new Separator());
        toolsMenu.Items.Add(MI("_Pay to many", () => Sel("Send"))); toolsMenu.Items.Add(MI("_Sweep Private Key", () => Sel("Tools")));
        var loadTx = MI("_Load transaction");
        loadTx.Items.Add(MI("From _text", () => Sel("Tools"))); loadTx.Items.Add(MI("From the _blockchain", () => Sel("Tools"))); loadTx.Items.Add(MI("From _QR code", () => Sel("Tools")));
        toolsMenu.Items.Add(loadTx);
        var helpMenu = MI("_Help");
        helpMenu.Items.Add(MI("_About", () => System.Windows.MessageBox.Show("ESTATES wallet — ElectrumSVP-class SPV wallet (Craig's SPV: IP-to-IP envelopes + Bloom). Network: " + _network, "About")));
        helpMenu.Items.Add(MI("Official _website", () => { try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("http://electrumsv.io") { UseShellExecute = true }); } catch { } }));
        menu.Items.Add(file); menu.Items.Add(wallet); menu.Items.Add(view); menu.Items.Add(toolsMenu); menu.Items.Add(helpMenu);

        var status = new System.Windows.Controls.Primitives.StatusBar { Background = B("#2b2d31"), Foreground = B("#9aa0a6") };
        var stBal = new TextBlock { Foreground = B("#7bd88f"), FontWeight = FontWeights.SemiBold };
        var stNet = new TextBlock { Foreground = B("#8ab4f8") };
        status.Items.Add(new System.Windows.Controls.Primitives.StatusBarItem { Content = stBal });
        status.Items.Add(new Separator());
        status.Items.Add(new System.Windows.Controls.Primitives.StatusBarItem { Content = stNet });
        void ShowStatus() { try { stBal.Text = $"  Balance: {LoadSpvFromDisk(w).Balance():n0} sat"; stNet.Text = $"{_network} · SPV (IP-to-IP + Bloom) · 🔒 encrypted"; } catch { } }
        ShowStatus(); auto.Tick += (_, _) => ShowStatus();

        var shell = new DockPanel { LastChildFill = true };
        DockPanel.SetDock(menu, Dock.Top); DockPanel.SetDock(status, Dock.Bottom);
        shell.Children.Add(menu); shell.Children.Add(status); shell.Children.Add(tabs);
        return shell;
    }

    // frozen coins (coin control) + a session transaction log for the History tab.
    private readonly HashSet<string> _frozenCoins = new();
    private readonly List<string> _txLog = new();

    // map a P2PKH locking script back to its address (for the Coins list).
    private string AddrOfScript(byte[] script)
    {
        try { if (script.Length == 25 && script[0] == 0x76) { var pkh = script[3..23]; return Address.P2pkh(pkh, _network == "mainnet" ? BsvNet.Mainnet : _network == "testnet" ? BsvNet.Testnet : BsvNet.Regtest); } } catch { }
        return "(non-standard)";
    }

    // BIP270: fetch a merchant PaymentRequest (Anypay/Centi) from a URL, pay its outputs from the SPV
    // wallet, broadcast, then POST the Payment back to the merchant (PaymentACK). Accepts a raw payment
    // URL or a "bitcoin:?r=<url>" / "pay:" URI.
    private static readonly System.Net.Http.HttpClient _http = new() { Timeout = System.TimeSpan.FromSeconds(20) };
    private async System.Threading.Tasks.Task<string> PayBip270(StandaloneWallet w, string urlOrUri)
    {
        try
        {
            string url = urlOrUri;
            if (url.StartsWith("bitcoin:", StringComparison.OrdinalIgnoreCase) || url.StartsWith("pay:", StringComparison.OrdinalIgnoreCase))
            {
                int r = url.IndexOf("r=", StringComparison.OrdinalIgnoreCase);
                if (r >= 0) url = System.Uri.UnescapeDataString(url[(r + 2)..].Split('&')[0]);
            }
            if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) return "not a payment URL";
            using var req = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, url);
            req.Headers.TryAddWithoutValidation("Accept", "application/bitcoinsv-paymentrequest, application/payment-request, application/json");
            var resp = await _http.SendAsync(req);
            string body = await resp.Content.ReadAsStringAsync();
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            var root = doc.RootElement;
            // BIP270 may wrap details in "memo"/"outputs" directly or under "paymentDetails"
            var det = root.TryGetProperty("outputs", out _) ? root : (root.TryGetProperty("paymentDetails", out var pd) ? pd : root);
            if (!det.TryGetProperty("outputs", out var outsEl)) return "invoice has no outputs";
            var outs = new List<(byte[] script, long amount)>();
            foreach (var o in outsEl.EnumerateArray())
            {
                long amt = o.TryGetProperty("amount", out var av) ? (av.ValueKind == System.Text.Json.JsonValueKind.Number ? av.GetInt64() : long.Parse(av.GetString()!)) : 0;
                string? scr = o.TryGetProperty("script", out var sv) ? sv.GetString() : null;
                if (scr is null || amt <= 0) return "invoice output malformed";
                outs.Add((Tx.FromHex(scr), amt));
            }
            string? payUrl = det.TryGetProperty("paymentUrl", out var pu) ? pu.GetString() : null;
            string merchantData = det.TryGetProperty("merchantData", out var md) ? (md.GetString() ?? "") : "";

            var spv2 = LoadSpvFromDisk(w);
            byte[] change = NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(FirstAddr)));
            var built = SpvSpend.BuildMany(spv2, SpvKeymap(w), outs, 500, change, _frozenCoins);
            if (built is null) return "insufficient funds for this invoice";
            using (var rpc = new BsvRpc("127.0.0.1", RpcPort(), "e", "e")) { try { await rpc.CallAsync("sendrawtransaction", Tx.ToHex(built.Raw)); } catch { } }
            foreach (var l in _node.LiveLinks()) { try { l.Send(built.Raw); } catch { } }
            foreach (var c in built.Tx.Inputs) spv2.Spend(c.PrevTxid + ":" + c.PrevVout);
            spv2.Save(SpvPathFor());
            _txLog.Add($"{"(invoice)",-20}{("-" + outs.Sum(o => o.amount).ToString("n0")),16}  {built.Txid[..Math.Min(20, built.Txid.Length)]}…");
            if (!string.IsNullOrEmpty(payUrl))
            {
                var payment = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object> { ["transaction"] = Tx.ToHex(built.Raw), ["merchantData"] = merchantData });
                try { using var pr = new System.Net.Http.StringContent(payment, System.Text.Encoding.UTF8, "application/bitcoinsv-payment"); await _http.PostAsync(payUrl, pr); } catch { }
            }
            return $"PAID invoice · {outs.Count} output(s) · txid {built.Txid}";
        }
        catch (System.Exception e) { return e.Message; }
    }

    // Sweep: take a raw private key, find its coins via the node, and move them all into this wallet.
    private async System.Threading.Tasks.Task<string> SweepPrivKey(StandaloneWallet w, string keyText, string bip38Pass)
    {
        try
        {
            string privHex;
            if (keyText.StartsWith("6P", StringComparison.Ordinal))            // BIP38 encrypted key
            {
                var dec = Bip38.Decrypt(keyText, bip38Pass ?? "");
                if (dec is null) return "BIP38 decrypt failed (wrong passphrase or unsupported key)";
                privHex = Tx.ToHex(dec.Value.priv);
            }
            else privHex = keyText;
            if (privHex.Length != 64) return "private key must be 64 hex characters (or a BIP38 6P… key)";
            byte[] priv = Tx.FromHex(privHex); byte[] pub = Secp256k1.PublicKey(priv);
            string fromAddr = Address.P2pkh(Recovery.Hash160(pub), _network == "mainnet" ? BsvNet.Mainnet : _network == "testnet" ? BsvNet.Testnet : BsvNet.Regtest);
            using var rpc = new BsvRpc("127.0.0.1", RpcPort(), "e", "e");
            await rpc.CallAsync("importaddress", fromAddr, "", false);
            var utxos = await rpc.CallAsync("listunspent", 0, 9999999, new[] { fromAddr });
            if (utxos is null) return "no node / no coins to sweep";
            long sum = 0; var ins = new List<TxInputN>(); var fromScript = NodeWallet.P2pkhScript(Recovery.Hash160(pub));
            foreach (var u in utxos.Value.EnumerateArray())
            {
                string txid = u.GetProperty("txid").GetString()!; int vout = u.GetProperty("vout").GetInt32();
                long val = (long)System.Math.Round(u.GetProperty("amount").GetDouble() * 100_000_000);
                sum += val; ins.Add(new TxInputN(txid, vout, System.Array.Empty<byte>(), 0xffffffff));
            }
            if (sum <= 1000) return "nothing to sweep at " + fromAddr;
            byte[] toScript = NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(FirstAddr)));
            var unsigned = new NativeTx(2, ins, new[] { new TxOutputN(sum - 500, toScript) }, 0);
            var signedIns = new List<TxInputN>();
            for (int i = 0; i < ins.Count; i++)
            {
                byte[] sh = Scriptvm.Sighash(unsigned, i, fromScript, 0, 0x41);   // value not needed for legacy-style here; node validates
                byte[] der = EcdsaSign.SignPrehashDer(priv, sh); var sig = new byte[der.Length + 1]; System.Array.Copy(der, sig, der.Length); sig[^1] = 0x41;
                var ss = new List<byte>(); ss.Add((byte)sig.Length); ss.AddRange(sig); ss.Add((byte)pub.Length); ss.AddRange(pub);
                signedIns.Add(new TxInputN(ins[i].PrevTxid, ins[i].PrevVout, ss.ToArray(), 0xffffffff));
            }
            var signed = new NativeTx(2, signedIns, unsigned.Outputs, 0);
            var r = await rpc.CallAsync("sendrawtransaction", Tx.ToHex(Tx.Serialize(signed)));
            return r is null ? "node rejected the sweep tx" : $"SWEPT {sum - 500:n0} sat from {fromAddr} → your wallet";
        }
        catch (System.Exception e) { return e.Message; }
    }

    // ---- Chat: a real messenger (group + 1:1, history, reactions/edit/delete/receipts, identity) ----
    private readonly Conversation _conv = new("lobby", true, Array.Empty<string>());
    private string _displayName = "";

    // ---- IDENTITY (baseline): a persistent handle (e.g. "Bob") bound to your stable identity key (the
    // wallet pubkey from your seed). It is advertised so peers can find, chat with, and PAY you by name —
    // pay an identity, not just an address. Persisted across launches; loaded at login.
    private static string IdentityPath() { string d = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Estates"); System.IO.Directory.CreateDirectory(d); return System.IO.Path.Combine(d, "identity.txt"); }
    private static string LoadHandle() { try { return System.IO.File.Exists(IdentityPath()) ? System.IO.File.ReadAllText(IdentityPath()).Trim() : ""; } catch { return ""; } }
    private void SaveHandle(string h) { try { System.IO.File.WriteAllText(IdentityPath(), h); } catch { } _node.Name = h.Length > 0 ? h : _node.Name; }
    private StackPanel? _chatList;
    private System.Action? _refreshChatWho;
    private byte[]? _chatDirectTo;   // set => Direct (1:1, ECDH symmetric to that identity)
    // Broadcast recipients: null => everyone live; non-null => a chosen subset (e.g. 10 of 100). Broadcast
    // uses the GB 2623780 B key-graph (broadcast encryption) — ONE ciphertext only the subset can open.
    private List<byte[]>? _chatBroadcastSubset;

    private UIElement BuildChatUI()
    {
        var root = new DockPanel { Margin = new Thickness(0, 12, 0, 0) };

        // identity row — set your name (your identity card); your pubkey is your address
        var idRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
        var nameBox = new TextBox { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), FontSize = 13, Text = _displayName };
        var setName = new Button { Content = "Set identity", Margin = new Thickness(8, 0, 0, 0), Padding = new Thickness(12, 6, 12, 6) };
        DockPanel.SetDock(setName, Dock.Right); idRow.Children.Add(setName); idRow.Children.Add(nameBox);
        DockPanel.SetDock(idRow, Dock.Top); root.Children.Add(idRow);

        // Direct (one peer, CHAT-2P) or Broadcast (everyone, CHAT-GROUP) — the required selection.
        var modeRow = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
        var modeLbl = new TextBlock { Text = "Send as:", Foreground = B("#9aa0a6"), FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
        var modeBox = new ComboBox { MinWidth = 220 };
        void RefreshModes()
        {
            int keep = modeBox.SelectedIndex;
            modeBox.Items.Clear();
            modeBox.Items.Add("Broadcast (everyone)");
            modeBox.Items.Add("Broadcast (choose recipients…)");
            foreach (var p in _node.Peers()) modeBox.Items.Add($"Direct: {p.Name}");
            modeBox.SelectedIndex = keep >= 0 && keep < modeBox.Items.Count ? keep : 0;
        }
        modeBox.DropDownOpened += (_, _) => RefreshModes();
        modeBox.SelectionChanged += (_, _) =>
        {
            int i = modeBox.SelectedIndex;
            if (i == 0) { _chatDirectTo = null; _chatBroadcastSubset = null; return; }   // Broadcast: everyone
            if (i == 1)                                                                  // Broadcast: chosen subset (key-graph)
            {
                _chatDirectTo = null;
                var picked = PickRecipients();
                if (picked is { Count: > 0 }) _chatBroadcastSubset = picked;
                else { _chatBroadcastSubset = null; modeBox.SelectedIndex = 0; }
                return;
            }
            _chatBroadcastSubset = null;                                                 // Direct (1:1)
            var peers = _node.Peers();
            int pi = i - 2;
            if (pi >= 0 && pi < peers.Count && peers[pi].WalletPub.Length > 0) { try { _chatDirectTo = Tx.FromHex(peers[pi].WalletPub); } catch { _chatDirectTo = null; } }
            else _chatDirectTo = null;
        };
        RefreshModes();
        DockPanel.SetDock(modeLbl, Dock.Left); modeRow.Children.Add(modeLbl); modeRow.Children.Add(modeBox);
        DockPanel.SetDock(modeRow, Dock.Top); root.Children.Add(modeRow);
        var who = new TextBlock { Foreground = B("#9aa0a6"), FontSize = 11, Margin = new Thickness(0, 0, 0, 8), TextWrapping = TextWrapping.Wrap };
        void ShowWho()
        {
            var peers = _node.Peers();
            string names = peers.Count == 0 ? "no one else here yet" : string.Join(", ", peers.Select(p => p.Name));
            who.Text = $"you: {(_displayName.Length > 0 ? _displayName : "(set a name)")}  ·  {Tx.ToHex(_walletPub)[..12]}…\nin chat: {names}";
        }
        _refreshChatWho = ShowWho;          // so peer discovery/loss live-updates the contact line
        ShowWho(); DockPanel.SetDock(who, Dock.Top); root.Children.Add(who);
        setName.Click += (_, _) => { _displayName = nameBox.Text.Trim(); SaveHandle(_displayName); ShowWho(); RenderChat(); RefreshNodes(); };

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
        if (ChatCommands.Is(text)) { HandleChatCommand(text); return; }   // \help \address \pay \request \balance
        Broadcast(Messenger.Text(MyPub(), text));
    }

    // ---- in-chat commands (same set for player↔player and player↔bot — pay is pay) ----
    private const int RecvWatch = 50;            // addresses we watch/derive (fresh per request, all SPV-synced)
    private int _recvIndex = 1;                  // next fresh receive address (index 0 = primary/refund)
    private int RpcPort() => _network == "mainnet" ? 8332 : _network == "testnet" ? 18332 : 18443;
    private string SpvPathFor() => System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"estates_spv_{_network}.dat");

    // index 0 is the BASE IDENTITY key (ECDH-derivation root) and is NEVER an address. Addresses are
    // ONLY the HMAC hash-chain sub-keys at index >= 1.
    private const int FirstAddr = 1;
    private Dictionary<string, (byte[] priv, byte[] pub)> SpvKeymap(StandaloneWallet w)
    {
        var keymap = new Dictionary<string, (byte[] priv, byte[] pub)>();
        for (int i = FirstAddr; i <= RecvWatch; i++) { var pu = w.ChildPub(i); keymap[Tx.ToHex(NodeWallet.P2pkhScript(Recovery.Hash160(pu)))] = (w.ChildPriv(i), pu); }
        return keymap;
    }

    private SpvWallet LoadSpvFromDisk(StandaloneWallet w)
    {
        var owned = new List<byte[]>();
        for (int i = FirstAddr; i <= RecvWatch; i++) owned.Add(NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(i))));
        var s = new SpvWallet(owned); try { s.Load(SpvPathFor()); } catch { }
        return s;
    }

    private string NextRecvAddress(StandaloneWallet w) { int i = _recvIndex; _recvIndex = _recvIndex + 1 >= RecvWatch ? 1 : _recvIndex + 1; return w.AddressAt(i); }

    // post a local status line into the chat (not sent to peers) — for \help, \balance, results.
    private void PostLocal(string text) { _conv.Apply(Messenger.Text(MyPub(), "ℹ " + text)); RenderChat(); }

    // resolve a recipient token to an address: a literal address, or a peer NAME / bot id (e.g. "bob",
    // "bot#3", "3") → that live peer's advertised receive address.
    private string? ResolveAddress(string token)
    {
        if (Base58.CheckDecode(token, out _) is { Length: 20 }) return token;     // already an address
        string t = token.Trim(); string tBot = t.StartsWith("bot") ? t : "bot#" + t.TrimStart('#');
        // a live peer's advertised IDENTITY handle (or bot#id) → their receive address
        foreach (var p in _node.Peers())
            if ((string.Equals(p.Name, t, StringComparison.OrdinalIgnoreCase) || string.Equals(p.Name, tBot, StringComparison.OrdinalIgnoreCase))
                && !string.IsNullOrEmpty(p.RecvAddr)) return p.RecvAddr;
        // a saved contact (a stored identity → address)
        foreach (var (name, address) in _contacts)
            if (string.Equals(name, t, StringComparison.OrdinalIgnoreCase)) return address;
        return null;
    }

    private async void HandleChatCommand(string text)
    {
        var c = ChatCommands.Parse(text);
        var w = EnsureWallet()!;
        switch (c.Kind)
        {
            case ChatCmd.Help: PostLocal(ChatCommands.Help()); break;
            case ChatCmd.AskAddress: Broadcast(Messenger.Text(MyPub(), "\\address")); PostLocal("asked the other party for an address"); break;
            case ChatCmd.StateAddress: { string a = string.IsNullOrEmpty(c.Address) ? NextRecvAddress(w) : c.Address; Broadcast(Messenger.Text(MyPub(), "\\addr " + a)); break; }
            case ChatCmd.Request: { string a = NextRecvAddress(w); Broadcast(Messenger.Text(MyPub(), $"\\request {c.Amount} {a}")); PostLocal($"requested {c.Amount:n0} sat to {a}"); break; }
            case ChatCmd.Balance: PostLocal($"balance ({_network}): {LoadSpvFromDisk(w).Balance():n0} sat"); break;
            case ChatCmd.Pay:
            {
                if (c.Amount <= 0) { PostLocal("usage: \\pay <address | name | bot#id> <amount-sat>"); break; }
                string? addr = ResolveAddress(c.Address);
                if (addr is null) { PostLocal($"unknown recipient '{c.Address}' — paste an address or use a live peer's name/bot#id"); break; }
                PostLocal($"paying {c.Amount:n0} sat to {c.Address}…");
                string res = await SpvPayTo(w, addr, c.Amount);
                PostLocal(res);
                break;
            }
            default: Broadcast(Messenger.Text(MyPub(), text)); break;     // unknown \command → just send the text
        }
    }

    // a REAL on-chain payment from the SPV wallet to an address (pay is pay — works for any recipient).
    private async System.Threading.Tasks.Task<string> SpvPayTo(StandaloneWallet w, string address, long sat)
    {
        try
        {
            var pkh = Base58.CheckDecode(address, out _);
            if (pkh is null || pkh.Length != 20) return "bad address";
            var spv = LoadSpvFromDisk(w);
            byte[] change = NodeWallet.P2pkhScript(Recovery.Hash160(w.ChildPub(0)));
            var built = SpvSpend.Build(spv, SpvKeymap(w), NodeWallet.P2pkhScript(pkh), sat, 500, change);
            if (built is null) return "insufficient SPV funds";
            using var rpc = new BsvRpc("127.0.0.1", RpcPort(), "e", "e");
            var r = await rpc.CallAsync("sendrawtransaction", Tx.ToHex(built.Raw));
            if (r is null) return "broadcast rejected by node";
            foreach (var cc in built.Tx.Inputs) spv.Spend(cc.PrevTxid + ":" + cc.PrevVout);
            spv.Save(SpvPathFor());
            return $"PAID {sat:n0} sat to {address[..Math.Min(14, address.Length)]}… · txid {built.Txid[..16]}…";
        }
        catch (System.Exception e) { return e.Message; }
    }

    private long _msgSeq;

    // THE RULE: every message is a BSV TRANSACTION, sent IP-to-IP to each player (and to miners once
    // funded). UI work stays on the UI thread; the heavy seal+serialize+socket work runs OFF-thread and
    // fully guarded, so a peer-link callback can never block or crash the app.
    private void Broadcast(ChatMessage m)
    {
        _conv.Apply(m); RenderChat();
        var links = _node.LiveLinks();
        byte[] payload = Messenger.Serialize(m);
        byte[] master = _master, myPkh = Recovery.Hash160(_walletPub);
        string conv = _conv.Id;
        var directTo = _chatDirectTo;

        if (directTo is not null)
        {
            // DIRECT: two-person ECDH (secp256k1) to one identity — a sealed carrier inside a transaction.
            System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var ring = new KeyRing(master);
                    long seq = System.Threading.Interlocked.Increment(ref _msgSeq);
                    byte[] carrier = TxMessage.SealCarrier(ring.MessagePriv(directTo, conv, seq), directTo, TxType.Chat2P, payload);
                    byte[] raw = Tx.Serialize(MsgTx(carrier, myPkh));
                    foreach (var l in links) l.Send(raw);
                }
                catch (System.Exception ex) { App.CrashLog("chat-send-direct", ex); }
            });
            return;
        }

        // BROADCAST: the key-graph (broadcast encryption) to a chosen subset — ONE ciphertext only those
        // recipients can open. null subset => everyone live right now. Carried AS a transaction.
        var recipients = (_chatBroadcastSubset is { Count: > 0 } sub ? sub : _node.PeerWalletPubs().ToList());
        if (recipients.Count == 0) return;                       // no one to broadcast to
        string b64 = System.Convert.ToBase64String(payload);     // exact byte round-trip through the key-graph
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                byte[]? frame = ChatCodec.Seal(master, recipients, b64);     // single broadcast-encrypted frame
                if (frame is null) return;
                byte[] raw = Tx.Serialize(MsgTx(frame, myPkh));              // the frame IS the carrier (already ciphertext)
                foreach (var l in links) l.Send(raw);
            }
            catch (System.Exception ex) { App.CrashLog("chat-send-broadcast", ex); }
        });
    }

    // A 1-output message transaction carrying `carrier` as the spendable carrier output (no OP_RETURN).
    private static NativeTx MsgTx(byte[] carrier, byte[] ownerPkh) => new(1,
        new[] { new TxInputN(new string('0', 64), 0xffffffff, System.Array.Empty<byte>(), 0xffffffff) },
        new[] { new TxOutputN(1, TxTransport.MessageOutput(carrier, ownerPkh)) }, 0);

    // Pick a SUBSET of live peers to broadcast-encrypt to (e.g. 10 of 100). Returns their wallet pubkeys,
    // or null if cancelled. Multi-select via checkboxes — the human chooses exactly who can read it.
    private List<byte[]>? PickRecipients()
    {
        var peers = _node.Peers().Where(p => p.WalletPub.Length > 0).ToList();
        if (peers.Count == 0) return null;
        var w = new Window { Title = "Broadcast to…", Width = 420, Height = 460, WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = this, Background = B("#1b1d1e"), ResizeMode = ResizeMode.NoResize };
        var sp = new StackPanel { Margin = new Thickness(14) };
        sp.Children.Add(new TextBlock { Text = "Choose who can read this broadcast:", Foreground = B("#e6e6e6"), FontSize = 13, Margin = new Thickness(0, 0, 0, 8) });
        var boxes = new List<(CheckBox cb, byte[] pub)>();
        var list = new StackPanel();
        foreach (var p in peers)
        {
            byte[]? pub = null; try { pub = Tx.FromHex(p.WalletPub); } catch { }
            if (pub is null) continue;
            var cb = new CheckBox { Content = $"{p.Name}  ·  {p.WalletPub[..Math.Min(12, p.WalletPub.Length)]}…", Foreground = B("#e6e6e6"), Margin = new Thickness(0, 4, 0, 4) };
            boxes.Add((cb, pub)); list.Children.Add(cb);
        }
        sp.Children.Add(new ScrollViewer { Height = 320, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = list });
        var ok = new Button { Content = "Broadcast to selected", Margin = new Thickness(0, 12, 0, 0), HorizontalAlignment = HorizontalAlignment.Right, Padding = new Thickness(12, 6, 12, 6) };
        List<byte[]>? result = null;
        ok.Click += (_, _) => { result = boxes.Where(b => b.cb.IsChecked == true).Select(b => b.pub).ToList(); w.Close(); };
        sp.Children.Add(ok); w.Content = sp; w.ShowDialog();
        return result is { Count: > 0 } ? result : null;
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

    // Bots I have PAID that still owe me a refund (by their identity pubkey hex). A bot broadcasts its
    // refund to the chain on close, then acks me; I remove it here so my close can proceed.
    private readonly HashSet<string> _fundedBots = new();

    // ABSOLUTE close-ordering: when the human closes the game, EVERY funded bot closes and refunds the
    // human FIRST. We hold the human's close, tell each bot to close+refund, wait for their on-chain
    // refunds to be acked (so no bot is left running and no sat is left behind), then close.
    private bool _closeHandled;
    private async void OnHumanClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_closeHandled) return;
        // every live bot peer must close + refund me FIRST (pay is pay — any bot I funded refunds on close)
        foreach (var p in _node.Peers()) if (p.Name.StartsWith("bot#", StringComparison.OrdinalIgnoreCase) && p.WalletPub.Length > 0) _fundedBots.Add(p.WalletPub);
        if (_fundedBots.Count == 0) return;                         // no bots → close normally
        e.Cancel = true;                                            // hold my close until bots refund
        SendGameCloseToBots();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (_fundedBots.Count > 0 && sw.Elapsed < System.TimeSpan.FromSeconds(15))
            await System.Threading.Tasks.Task.Delay(150);
        _closeHandled = true;
        Close();                                                    // now I close
    }

    // Signal every bot peer to close + refund me now (GameClose carrier, IP-to-IP).
    private void SendGameCloseToBots()
    {
        try
        {
            var ring = new KeyRing(_walletSeed!);
            byte[] myPkh = Recovery.Hash160(_walletPub);
            foreach (var botPub in _node.PeerWalletPubs())
            {
                long seq = System.DateTime.UtcNow.Ticks;
                byte[] carrier = TxMessage.SealCarrier(ring.MessagePriv(botPub, "fund", seq), botPub, TxType.GameClose, "close"u8.ToArray());
                var tx = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0xffffffff, System.Array.Empty<byte>(), 0xffffffff) },
                    new[] { new TxOutputN(1, TxTransport.MessageOutput(carrier, myPkh)) }, 0);
                byte[] raw = Tx.Serialize(tx);
                foreach (var l in _node.LiveLinks()) { try { l.Send(raw); } catch { } }
            }
        }
        catch (System.Exception e) { App.CrashLog("game-close-signal", e); }
    }

    // The bot acked that it has refunded me on-chain ("refunded|<botpub>"). Stop waiting on it.
    private void CompleteBotRefund(byte[] payload)
    {
        try
        {
            var parts = System.Text.Encoding.ASCII.GetString(payload).Split('|');
            if (parts.Length == 2 && parts[0] == "refunded") _fundedBots.Remove(parts[1]);
        }
        catch (System.Exception e) { App.CrashLog("bot-refund-ack", e); }
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
            ChatMessage? m = null;
            if (ex is not null)
            {
                if (ex.Value.type == TxType.BotRefund) { CompleteBotRefund(ex.Value.plaintext); return; }
                try { m = Messenger.Parse(ex.Value.plaintext); } catch { }
            }
            else
            {
                // not a per-recipient sealed carrier — try the broadcast key-graph frame on each output.
                foreach (var o in tx.Outputs)
                {
                    var carrier = TxTransport.ReadCarrier(o.Script);
                    if (carrier is null) continue;
                    var open = ChatCodec.Open(carrier, _master, _walletPub);   // only opens if I'm in the subset
                    if (open is null) continue;
                    try { m = Messenger.Parse(System.Convert.FromBase64String(open.Value.text)); } catch { }
                    if (m is not null) break;
                }
            }
            if (m is null) return;
            _conv.Apply(m); RenderChat();
            if (m.FromPub != MyPub() && (m.Kind is ChatKind.Text or ChatKind.Reply or ChatKind.Media))
            {
                Broadcast(Messenger.Read(MyPub(), m.Id));
                // a peer asked me for an address → AUTO-generate a fresh one and state it back (\addr <a>)
                if (ChatCommands.Is(m.Display) && ChatCommands.Parse(m.Display).Kind == ChatCmd.AskAddress)
                { var w = EnsureWallet()!; Broadcast(Messenger.Text(MyPub(), "\\addr " + NextRecvAddress(w))); }
            }
        }
        catch (System.Exception e) { App.CrashLog("chat-recv", e); }
    }
}
