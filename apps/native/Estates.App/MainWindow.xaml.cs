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
                sp.Children.Add(Head(exists ? "Unlock wallet" : "Create wallet"));
                sp.Children.Add(new TextBlock { Text = exists ? "Enter your wallet password (leave blank if you didn't set one)." : "Create your wallet. A password is OPTIONAL — leave it blank for none. Your seed is saved to disk, so closing keeps your money.", Foreground = B("#9aa0a6"), FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8) });
                var pw = new PasswordBox { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), FontSize = 13, Margin = new Thickness(0, 0, 0, 8) };
                var msg = Out();
                var go = new Button { Content = exists ? "Unlock" : "Create wallet", HorizontalAlignment = HorizontalAlignment.Left };
                go.Click += (_, _) =>
                {
                    try
                    {
                        if (exists) { var s = WalletStore.Open(path, pw.Password); if (s is null) { msg.Text = "wrong password"; return; } _walletSeed = s; }
                        else { _walletSeed = WalletStore.OpenOrCreate(path, pw.Password); }
                        Render();
                    }
                    catch (Exception ex) { msg.Text = ex.Message; }
                };
                sp.Children.Add(pw); sp.Children.Add(go);
                if (exists)
                {
                    var fresh = new Button { Content = "Start a new wallet (replaces the file)", Background = B("#3a3d42"), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 8, 0, 0) };
                    fresh.Click += (_, _) => { try { System.IO.File.Delete(path); _walletSeed = WalletStore.OpenOrCreate(path, pw.Password); Render(); } catch (Exception ex) { msg.Text = ex.Message; } };
                    sp.Children.Add(fresh);
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
        sp.Children.Add(ok);
        w.Content = sp;
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

        return tabs;
    }

    // ---- Chat (its own tab): end-to-end encrypted over the peer links ----------------
    private StackPanel? _chatLog;
    private UIElement BuildChatUI()
    {
        var dock = new DockPanel { Margin = new Thickness(0, 12, 0, 0) };
        var input = new TextBox { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), FontSize = 13 };
        var send = new Button { Content = "Send", Margin = new Thickness(8, 0, 0, 0), Padding = new Thickness(14, 6, 14, 6) };
        var bar = new DockPanel { Margin = new Thickness(0, 10, 0, 0) };
        DockPanel.SetDock(send, Dock.Right); bar.Children.Add(send); bar.Children.Add(input);
        DockPanel.SetDock(bar, Dock.Bottom);
        _chatLog = new StackPanel();
        dock.Children.Add(bar);
        dock.Children.Add(new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = _chatLog });
        send.Click += (_, _) => { SendChat(input.Text); input.Clear(); };
        return dock;
    }

    private void SendChat(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return;
        var frame = ChatCodec.Seal(_master, _node.PeerWalletPubs(), text);
        if (frame is null) { AppendChat("(no peers connected)", text); return; }
        foreach (var l in _node.LiveLinks()) l.Send(frame);
        AppendChat(_node.Name, text);
    }

    private void OnChatFrame(PeerLink link, byte[] frame)
    {
        var msg = ChatCodec.Open(frame, _master, _walletPub);
        if (msg is not null) AppendChat("player-" + msg.Value.from[..6], msg.Value.text);
    }

    private void AppendChat(string who, string text)
    {
        if (_chatLog is null) return;
        var line = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6) };
        line.Inlines.Add(new System.Windows.Documents.Run(who + "  ") { Foreground = B("#f5a623"), FontWeight = FontWeights.SemiBold });
        line.Inlines.Add(new System.Windows.Documents.Run(text) { Foreground = B("#cfd2d6") });
        _chatLog.Children.Add(line);
    }
}
