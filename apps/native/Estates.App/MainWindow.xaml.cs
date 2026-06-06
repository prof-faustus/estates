using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Estates.Core;

namespace Estates.App;

/// <summary>
/// The native ESTATES window — tabbed: Lobby, Game, Wallet, Chat (switch with the tabs).
/// A bot is just another node YOU run (estates.exe --bot) and fully control. No server;
/// closing the window ends everything. The wallet talks to YOUR BSV node; the game board
/// is its own tab; chat is end-to-end encrypted over the peer links.
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

    // HARD RULE: a game cannot be started without funding. Refuse unless the wallet on the
    // selected network is reachable and holds funds.
    private bool RequireFunding(string net)
    {
        var node = NodeFor(net);
        if (!node.Reachable(out var info)) { StartMsg.Text = $"Cannot start a game: fund your wallet first — your {net} node is unreachable ({info})."; return false; }
        decimal bal;
        try { bal = node.GetBalance(); } catch (Exception ex) { StartMsg.Text = "Cannot start a game: " + ex.Message; return false; }
        if (bal <= 0) { StartMsg.Text = $"Cannot start a game: your {net} wallet has 0 funds. Fund it before starting."; return false; }
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
    private NodeRpc? _gameNode;   // every move is anchored on chain through this node
    private readonly List<(int id, string name, string txid)> _heldNfts = new();   // deed/card NFTs you hold
    private string? _genesisTxid;   // the table-setup transaction that opened the table on-chain

    private void StartGame(string network, int seats)
    {
        _gameNode = NodeFor(network);   // real/testnet use your node; regtest = the test rail
        try
        {
            // table-setup transaction (§6.1): open the table ON-CHAIN — mint the title NFTs to the
            // bank, issue each seat its starting sats, bind params. Keys are unique Type-42 sub-keys.
            byte[] root = _walletSeed ?? _master;
            var seatPubs = new List<byte[]>();
            for (int i = 0; i < seats; i++) seatPubs.Add(Type42.PublicKey(Type42.UniqueKey(root, $"seat-{i}-{Guid.NewGuid():N}")));
            byte[] bankPub = Type42.PublicKey(Type42.UniqueKey(root, "bank-" + Guid.NewGuid().ToString("N")));
            var genesis = OnChain.TableSetup(_gameNode, seatPubs, bankPub, network, 1500, 100000);
            _genesisTxid = genesis.Txid;
        }
        catch (Exception ex) { StartMsg.Text = "table-setup transaction failed: " + ex.Message; return; }

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
            inner.Children.Add(new TextBlock { Text = "table opened on-chain · genesis " + _genesisTxid[..16] + "…", Foreground = B("#9aa0a6"), FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 0, 0, 10) });
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
            try
            {
                string commit = a.Dice != null ? $"{type}:{a.Dice[0]},{a.Dice[1]}@t{_game.TurnIndex}" : $"{type}@t{_game.TurnIndex}";
                if (commit.Length > 40) commit = commit[..40];
                string txid = OnChain.AnchorMove(_gameNode!, System.Text.Encoding.ASCII.GetBytes(commit));
                _game.Log.Add($"on-chain {commit} -> {txid}");
            }
            catch (Exception ex) { _game.Log.Add($"(on-chain anchor failed: {ex.Message})"); }

            if (bought is int pid)   // buying mints the deed as a 1-sat NFT to YOUR wallet
            {
                try
                {
                    byte[] pkh = Recovery.Hash160(Cipher.PublicKey(_walletSeed ?? _master));
                    string nm = Params.Instance.Board[pid].Name;
                    string deed = $"DEED:{pid}:{(nm.Length > 18 ? nm[..18] : nm)}";
                    string nftTx = OnChain.MintDeed(_gameNode!, System.Text.Encoding.ASCII.GetBytes(deed), pkh);
                    _heldNfts.Add((pid, nm, nftTx));
                    _game.Log.Add($"deed NFT '{nm}' -> your wallet (nft {nftTx[..12]}...)");
                }
                catch (Exception ex) { _game.Log.Add($"(deed NFT mint failed: {ex.Message})"); }
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
        TextBox Field() => new() { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), Margin = new Thickness(0, 2, 0, 6), FontFamily = new FontFamily("Consolas"), FontSize = 12, TextWrapping = TextWrapping.Wrap };
        TextBlock Head(string t) => new() { Text = t, Foreground = B("#e6e6e6"), FontSize = 15, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 14, 0, 6) };
        TextBlock Out() => new() { Foreground = B("#f5a623"), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0), FontFamily = new FontFamily("Consolas") };
        TextBlock Lbl(string t) => new() { Text = t, Foreground = B("#9aa0a6"), FontSize = 11 };

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

    private NodeRpc NodeFor(string net) => net switch
    {
        "regtest" => NodeRpc.Regtest(),
        "testnet" => new NodeRpc("http://127.0.0.1:18332/", "e", "e"),   // your testnet node
        _ => new NodeRpc("http://127.0.0.1:8332/", "e", "e"),            // your mainnet (real) node
    };

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

    // ---- Electrum-style wallet: tabs Info/History/Send/Receive/Addresses/Coins/Contacts/Console/Tools/NFTs ----
    private UIElement ElectrumWallet(System.Action relock)
    {
        var node = NodeFor(_network);
        byte ver = _network == "mainnet" ? (byte)0x00 : (byte)0x6f;
        TextBox F() => new() { Background = B("#171819"), Foreground = B("#e6e6e6"), BorderThickness = new Thickness(0), Padding = new Thickness(8), Margin = new Thickness(0, 2, 0, 6), FontFamily = new FontFamily("Consolas"), FontSize = 12, TextWrapping = TextWrapping.Wrap, AcceptsReturn = true };
        TextBox Mono(int h) => new() { IsReadOnly = true, Background = B("#171819"), Foreground = B("#cfd2d6"), FontFamily = new FontFamily("Consolas"), FontSize = 11, BorderThickness = new Thickness(0), Padding = new Thickness(8), Height = h, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        TextBlock L(string t) => new() { Text = t, Foreground = B("#9aa0a6"), FontSize = 11 };
        TextBlock O() => new() { Foreground = B("#f5a623"), FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0), FontFamily = new FontFamily("Consolas") };
        Button Btn(string t) => new() { Content = t, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 6, 0, 0) };
        TabItem Tab(string h, StackPanel body) => new() { Header = h, Content = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Content = new StackPanel { Margin = new Thickness(12), Children = { body } } } };
        var tabs = new TabControl { Background = B("#1e1f22"), BorderThickness = new Thickness(0) };

        // Info
        var info = new StackPanel();
        info.Children.Add(new TextBlock { Text = $"Network: {_network}", Foreground = B("#e6e6e6"), FontSize = 14, FontWeight = FontWeights.Bold });
        var bal = new TextBlock { Foreground = B("#7bd88f"), FontSize = 22, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 6, 0, 2) };
        var nstat = L("");
        void Refresh() { if (node.Reachable(out var i)) { nstat.Text = "node: " + i; try { bal.Text = node.GetBalance() + " BSV"; } catch (Exception e) { bal.Text = e.Message; } } else { nstat.Text = "node unreachable: " + i; bal.Text = "—"; } }
        Refresh();
        var rb = Btn("Refresh"); rb.Click += (_, _) => Refresh();
        info.Children.Add(bal); info.Children.Add(nstat); info.Children.Add(rb);
        info.Children.Add(L("Recovery seed (back this up)")); var sb0 = F(); sb0.IsReadOnly = true; sb0.Text = Tx.ToHex(_walletSeed!); info.Children.Add(sb0);
        info.Children.Add(L("Address from seed")); var sa0 = F(); sa0.IsReadOnly = true; sa0.Text = Wallet.Address(Cipher.PublicKey(_walletSeed!), ver); info.Children.Add(sa0);
        var lk = Btn("Lock wallet"); lk.Click += (_, _) => relock(); info.Children.Add(lk);
        tabs.Items.Add(Tab("Info", info));

        // History
        var hist = new StackPanel(); var hl = Mono(380);
        void LoadHist() { try { var s = new System.Text.StringBuilder(); foreach (var t in node.Call("listtransactions", "*", 100).EnumerateArray()) { string cat = t.TryGetProperty("category", out var c) ? c.GetString()! : ""; decimal am = t.TryGetProperty("amount", out var a) ? a.GetDecimal() : 0; long cf = t.TryGetProperty("confirmations", out var x) ? x.GetInt64() : 0; string id = t.TryGetProperty("txid", out var ti) ? ti.GetString()! : ""; s.Insert(0, $"{cat,-8}{am,15} BSV  conf {cf,-5}{id}\n"); } hl.Text = s.ToString(); } catch (Exception e) { hl.Text = e.Message; } }
        LoadHist(); var hr = Btn("Refresh history"); hr.Click += (_, _) => LoadHist(); hist.Children.Add(hr); hist.Children.Add(hl); tabs.Items.Add(Tab("History", hist));

        // Send + pay-to-many
        var send = new StackPanel(); var to = F(); var amt = F(); var so = O();
        var sbtn = Btn("Send"); sbtn.Click += (_, _) => { try { so.Text = "txid: " + node.SendToAddress(to.Text.Trim(), decimal.Parse(amt.Text.Trim())); } catch (Exception e) { so.Text = e.Message; } };
        send.Children.Add(L("Pay to (address)")); send.Children.Add(to); send.Children.Add(L("Amount (BSV)")); send.Children.Add(amt); send.Children.Add(sbtn); send.Children.Add(so);
        send.Children.Add(L("Pay to many — one 'address,amount' per line")); var ptm = F(); ptm.Height = 90; var po = O();
        var pbtn = Btn("Pay to many"); pbtn.Click += (_, _) => { try { var outs = new Dictionary<string, decimal>(); foreach (var ln in ptm.Text.Split('\n')) { var p = ln.Split(','); if (p.Length == 2) outs[p[0].Trim()] = decimal.Parse(p[1].Trim()); } po.Text = "txid: " + node.Call("sendmany", "", outs).GetString(); } catch (Exception e) { po.Text = e.Message; } };
        send.Children.Add(ptm); send.Children.Add(pbtn); send.Children.Add(po); tabs.Items.Add(Tab("Send", send));

        // Receive
        var recv = new StackPanel(); var ra = F(); ra.IsReadOnly = true; var rbtn = Btn("New address"); rbtn.Click += (_, _) => { try { ra.Text = node.GetNewAddress(); } catch (Exception e) { ra.Text = e.Message; } };
        recv.Children.Add(rbtn); recv.Children.Add(ra); tabs.Items.Add(Tab("Receive", recv));

        // Addresses (HD, from seed)
        var addrs = new StackPanel(); var al = Mono(380); var s2 = new System.Text.StringBuilder();
        foreach (var a in Wallet.Addresses(_walletSeed!, 20, ver)) s2.AppendLine($"#{a.Index,-3} {a.Address}"); al.Text = s2.ToString();
        addrs.Children.Add(L("Your HD addresses (derived from the seed)")); addrs.Children.Add(al); tabs.Items.Add(Tab("Addresses", addrs));

        // Coins (UTXOs + freeze)
        var coins = new StackPanel(); var cl = Mono(300);
        void LoadCoins() { try { var s = new System.Text.StringBuilder(); foreach (var u in node.ListUnspent()) s.AppendLine($"{u.amount,15} BSV  {u.txid}:{u.vout}"); cl.Text = s.ToString(); } catch (Exception e) { cl.Text = e.Message; } }
        LoadCoins(); var cr = Btn("Refresh coins"); cr.Click += (_, _) => LoadCoins();
        var fin = F(); var fo = O(); var fb = Btn("Freeze (txid:vout)"); fb.Click += (_, _) => { try { var p = fin.Text.Trim().Split(':'); node.Call("lockunspent", false, new[] { new Dictionary<string, object> { ["txid"] = p[0], ["vout"] = long.Parse(p[1]) } }); fo.Text = "frozen"; } catch (Exception e) { fo.Text = e.Message; } };
        coins.Children.Add(cr); coins.Children.Add(cl); coins.Children.Add(L("Freeze a coin")); coins.Children.Add(fin); coins.Children.Add(fb); coins.Children.Add(fo); tabs.Items.Add(Tab("Coins", coins));

        // Contacts
        var cont = new StackPanel(); var ccl = Mono(220); void LoadC() { var s = new System.Text.StringBuilder(); foreach (var c in _contacts) s.AppendLine($"{c.name}  {c.address}"); ccl.Text = s.ToString(); } LoadC();
        var cnm = F(); var cad = F(); var cab = Btn("Add contact"); cab.Click += (_, _) => { _contacts.Add((cnm.Text.Trim(), cad.Text.Trim())); LoadC(); };
        cont.Children.Add(ccl); cont.Children.Add(L("name")); cont.Children.Add(cnm); cont.Children.Add(L("address")); cont.Children.Add(cad); cont.Children.Add(cab); tabs.Items.Add(Tab("Contacts", cont));

        // Console
        var con = new StackPanel(); var cmd = F(); var carg = F(); var cres = Mono(240); var crun = Btn("Run");
        crun.Click += (_, _) => { try { var ps = string.IsNullOrWhiteSpace(carg.Text) ? Array.Empty<object>() : carg.Text.Split(' ').Select(x => long.TryParse(x, out var n) ? (object)n : x).ToArray(); cres.Text = node.Call(cmd.Text.Trim(), ps).ToString(); } catch (Exception e) { cres.Text = e.Message; } };
        con.Children.Add(L("RPC method")); con.Children.Add(cmd); con.Children.Add(L("args (space-separated)")); con.Children.Add(carg); con.Children.Add(crun); con.Children.Add(cres); tabs.Items.Add(Tab("Console", con));

        // Tools: sign/verify message + load/broadcast raw tx
        var tools = new StackPanel();
        tools.Children.Add(new TextBlock { Text = "Sign message", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        var ga = F(); var gm = F(); var go = O(); var gb = Btn("Sign"); gb.Click += (_, _) => { try { go.Text = node.SignMessage(ga.Text.Trim(), gm.Text); } catch (Exception e) { go.Text = e.Message; } };
        tools.Children.Add(L("address")); tools.Children.Add(ga); tools.Children.Add(L("message")); tools.Children.Add(gm); tools.Children.Add(gb); tools.Children.Add(go);
        tools.Children.Add(new TextBlock { Text = "Verify message", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold, Margin = new Thickness(0, 12, 0, 0) });
        var va = F(); var vs = F(); var vm = F(); var vo = O(); var vb = Btn("Verify"); vb.Click += (_, _) => { try { vo.Text = node.VerifyMessage(va.Text.Trim(), vs.Text.Trim(), vm.Text) ? "VALID" : "INVALID"; } catch (Exception e) { vo.Text = e.Message; } };
        tools.Children.Add(L("address")); tools.Children.Add(va); tools.Children.Add(L("signature")); tools.Children.Add(vs); tools.Children.Add(L("message")); tools.Children.Add(vm); tools.Children.Add(vb); tools.Children.Add(vo);
        tools.Children.Add(new TextBlock { Text = "Load / broadcast raw transaction", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold, Margin = new Thickness(0, 12, 0, 0) });
        var tr = F(); tr.Height = 80; var tro = O();
        var tdec = Btn("Decode"); tdec.Click += (_, _) => { try { tro.Text = node.Call("decoderawtransaction", tr.Text.Trim()).ToString(); } catch (Exception e) { tro.Text = e.Message; } };
        var tbc = Btn("Broadcast"); tbc.Click += (_, _) => { try { tro.Text = "txid: " + node.SendRawTransaction(tr.Text.Trim()); } catch (Exception e) { tro.Text = e.Message; } };
        tools.Children.Add(tr); var trb = new StackPanel { Orientation = Orientation.Horizontal }; trb.Children.Add(tdec); trb.Children.Add(tbc); tools.Children.Add(trb); tools.Children.Add(tro);
        tabs.Items.Add(Tab("Tools", tools));

        // NFTs — the deeds/cards you hold, as encrypted 1-sat BSV NFTs
        var nft = new StackPanel();
        nft.Children.Add(new TextBlock { Text = "Your NFTs — encrypted 1-sat BSV deeds & cards", Foreground = B("#e6e6e6"), FontWeight = FontWeights.Bold });
        var nl = Mono(360);
        void LoadNfts() { var s = new System.Text.StringBuilder(); foreach (var n in _heldNfts) s.AppendLine($"{n.name}  (property #{n.id})  nft txid {n.txid}"); if (_heldNfts.Count == 0) s.AppendLine("none yet — buy a property in a game and its deed NFT lands here."); nl.Text = s.ToString(); }
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
        var frame = ChatCodec.Seal(_walletPub, _node.PeerWalletPubs(), text);
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
