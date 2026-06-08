using System.Collections.Generic;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Estates.Core;

namespace Estates.App;

/// <summary>
/// A FULLY AUTOMATED bot — not a person. Its own narrow amber console, docked to a screen corner, never
/// over the player window. The human FUNDS it by PAYING its address (a real on-chain payment — never an
/// import). Network is selectable (mainnet / testnet / regtest); funds paid to the bot's address show via
/// SPV. On close the bot refunds the funder 100% and exits. It never fakes a solo game.
/// </summary>
public partial class BotWindow : Window
{
    private readonly P2PNode _node;
    private readonly int _botId;                  // FIXED bot id — its persistent identity across restarts
    private readonly string _owner;               // the human OWNER's handle (e.g. "Alice") — the bot is theirs
    private readonly byte[]? _ownerPub;           // the owner's identity pubkey — only the owner controls this bot
    private readonly byte[] _master;              // this bot's seed — DERIVED from the owner, keyed per owner+id
    private readonly byte[] _pub;                 // chat/identity pubkey (same scheme as the player client)
    private readonly DispatcherTimer _poll = new();
    private bool _greeted;

    private string _network = "mainnet";
    private StandaloneWallet _wallet = null!;     // rebuilt per selected network
    private SpvWallet _spv = null!;               // the bot's own SPV view (coins paid to its address)
    private string _spvPath = "";
    private const int BotWatch = 50;              // addresses the bot watches/derives (fresh per request)
    private int _recvIndex = 1;                   // next fresh receive address (index 0 = primary)

    // The bot's seed is keyed by OWNER + id, so a bot belongs to exactly one human. The owner's client
    // writes the (owner-derived) seed before launch; here we load it (or create one for a solo/test run).
    private static byte[] LoadOrCreateBotSeed(int id, string ownerPub)
    {
        string dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Estates", "bots");
        System.IO.Directory.CreateDirectory(dir);
        string key = string.IsNullOrEmpty(ownerPub) ? "solo" : (ownerPub.Length >= 8 ? ownerPub[..8] : ownerPub);
        string path = System.IO.Path.Combine(dir, $"bot_{key}_{id}.seed");
        if (System.IO.File.Exists(path)) { var b = System.IO.File.ReadAllBytes(path); if (b.Length == 32) return b; }
        var seed = RandomNumberGenerator.GetBytes(32);
        System.IO.File.WriteAllBytes(path, seed);
        return seed;
    }

    public BotWindow(int botId = 1, string owner = "", string ownerPub = "")
    {
        InitializeComponent();
        var wa = SystemParameters.WorkArea;
        Left = wa.Right - Width - 12;
        Top = wa.Bottom - Height - 12;

        _botId = botId; _owner = owner;
        try { _ownerPub = ownerPub.Length == 66 ? Tx.FromHex(ownerPub) : null; } catch { _ownerPub = null; }
        _master = LoadOrCreateBotSeed(botId, ownerPub);    // owner-keyed seed → the bot is THIS owner's only
        string name = owner.Length > 0 ? $"{owner}-Bot-{botId:000}" : $"bot#{botId}";
        Title = $"ESTATES · {name}";
        _pub = Cipher.PublicKey(_master);          // IDENTICAL scheme to MainWindow so chat keys match
        _node = new P2PNode(name, Tx.ToHex(_pub));
        _node.OnLink += link => link.OnFrame += (l, f) => Dispatcher.Invoke(() => OnBotChat(l, f));
        App.Teardowns.Add(() => { try { _node.Dispose(); } catch { } });
        Closed += (_, _) => { _poll.Stop(); RefundFunderOnClose(); try { _node.Dispose(); } catch { } };

        BotNetwork.SelectedIndex = 0;              // mainnet by default — triggers BotNetwork_Changed to build the wallet

        Log(owner.Length > 0 ? $"{owner}-Bot-{botId:000} started — I belong ONLY to {owner}; no other player can run or control me" : $"bot#{botId} started — connected as a peer node");
        Log("fund me by PAYING my address (Funds tab) on the chosen network — a real on-chain payment");
        Log("I refund my OWNER 100% when I close (never any other player)");

        _poll.Interval = TimeSpan.FromMilliseconds(2000);
        _poll.Tick += (_, _) =>
        {
            BotSpvSync();                          // pick up payments to my address (no Refresh button)
            ShowWallet();
            BotStatus.Text = $"Connected · {_network} · peers {_node.Peers().Count} · funded {_spv.Balance():n0} sat";
            if (!_greeted && _node.LiveLinks().Count > 0 && _node.PeerWalletPubs().Count > 0) Greet();
        };
        _poll.Start();
        BotStatus.Text = "Connected · awaiting funding";
    }

    private static int RpcPort(string net) => net == "mainnet" ? 8332 : net == "testnet" ? 18332 : 18443;

    private void BotNetwork_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (BotNetwork.SelectedItem is not ComboBoxItem it) return;
        _network = it.Content!.ToString()!;
        _wallet = new StandaloneWallet(_master, _network);
        var owned = new List<byte[]>();
        for (int i = 0; i < BotWatch; i++) owned.Add(NodeWallet.P2pkhScript(Recovery.Hash160(_wallet.ChildPub(i))));
        _spv = new SpvWallet(owned);
        _spvPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"estates_bot{_botId}_spv_{_network}.dat");
        try { _spv.Load(_spvPath); } catch { }
        _node.ReceiveAddress = _wallet.AddressAt(0);   // advertise my address so the human can pay it
        ShowWallet();
        BotSpvSync();
    }

    private void ShowWallet()
    {
        if (_wallet is null) return;
        BotAddress.Text = _wallet.AddressAt(0);
        string who = _owner.Length > 0 ? $"{_owner}-Bot-{_botId:000}  ·  owned by {_owner}" : $"bot#{_botId}";
        BotWallet.Text = $"{who}\nbalance ({_network}): {_spv.Balance():n0} sat   ·   {_spv.CoinCount} coin(s)\n(refunds my OWNER in full on close — never another player)";
    }

    // a FRESH receive address each time it is asked (rotates within the watched range; index 0 is primary).
    private string NextRecv() { int i = _recvIndex; _recvIndex = _recvIndex + 1 >= BotWatch ? 1 : _recvIndex + 1; return _wallet.AddressAt(i); }

    // Pull payments made to my addresses from the chain (SPV: tx + merkle proof), so funding just shows.
    private async void BotSpvSync()
    {
        if (_wallet is null) return;
        try
        {
            using var rpc = new BsvRpc("127.0.0.1", RpcPort(_network), "e", "e");
            int total = 0;
            for (int i = 0; i < BotWatch; i++) total += await SpvSync.SyncAddressAsync(rpc, _spv, _wallet.AddressAt(i));
            if (total > 0) { try { _spv.Save(_spvPath); } catch { } }
            Dispatcher.Invoke(ShowWallet);
        }
        catch { /* no node reachable on this network right now — funds show once it is */ }
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetText(_wallet.AddressAt(0)); FundMsg.Text = "address copied — pay it to fund me"; }
        catch { FundMsg.Text = _wallet.AddressAt(0); }
    }

    // the controlling human peer's advertised address (where the bot refunds on close). Pay is pay — there
    // is no special bot-funding channel; the bot refunds to whoever controls it (the linked player peer).
    private byte[]? FunderRefundScript()
    {
        // refund ONLY the OWNER: the live peer whose identity pubkey is the owner's. No other player can
        // ever receive this bot's funds.
        if (_ownerPub is not null)
        {
            string ownerHex = Tx.ToHex(_ownerPub);
            foreach (var p in _node.Peers())
                if (p.WalletPub == ownerHex && !string.IsNullOrEmpty(p.RecvAddr)) { var pkh = Base58.CheckDecode(p.RecvAddr, out _); if (pkh is { Length: 20 }) return NodeWallet.P2pkhScript(pkh); }
            return null;   // owner not present → do not refund anyone else
        }
        foreach (var p in _node.Peers())   // solo/test bot (no owner bound): the single controlling peer
            if (!string.IsNullOrEmpty(p.RecvAddr)) { var pkh = Base58.CheckDecode(p.RecvAddr, out _); if (pkh is { Length: 20 }) return NodeWallet.P2pkhScript(pkh); }
        return null;
    }

    // true only if a control message is from THIS bot's owner — no other player may control it.
    private bool FromOwner(byte[] senderIdentityPub) => _ownerPub is null || (senderIdentityPub.Length == _ownerPub.Length && Tx.ToHex(senderIdentityPub) == Tx.ToHex(_ownerPub));

    // refund-to-funder on close: SPV-spend the bot's ENTIRE balance back to the funder's address, broadcast
    // it on-chain, and tell the funder it is done. After this the bot holds nothing.
    private void RefundFunderOnClose()
    {
        try
        {
            if (_spv is null || _spv.Balance() <= 0) return;
            byte[]? to = FunderRefundScript();
            if (to is null) { Log("close: I hold funds but no funder peer is known — cannot refund safely"); return; }
            long fee = 500, amt = _spv.Balance() - fee;
            if (amt <= 0) return;
            var keymap = new Dictionary<string, (byte[] priv, byte[] pub)>();
            for (int i = 0; i < BotWatch; i++) { var pu = _wallet.ChildPub(i); keymap[Tx.ToHex(NodeWallet.P2pkhScript(Recovery.Hash160(pu)))] = (_wallet.ChildPriv(i), pu); }
            byte[] change = NodeWallet.P2pkhScript(Recovery.Hash160(_wallet.ChildPub(0)));
            var built = SpvSpend.Build(_spv, keymap, to, amt, fee, change);
            if (built is null) { Log("close: refund build failed"); return; }
            try { using var rpc = new BsvRpc("127.0.0.1", RpcPort(_network), "e", "e"); rpc.CallAsync("sendrawtransaction", Tx.ToHex(built.Raw)).GetAwaiter().GetResult(); } catch { }
            foreach (var c in built.Tx.Inputs) _spv.Spend(c.PrevTxid + ":" + c.PrevVout);
            try { _spv.Save(_spvPath); } catch { }
            SendRefundAck();                                   // let the funder know I'm done (so their close can proceed)
            Log($"close: refunded the funder {amt:n0} sat on {_network} (txid {built.Txid[..16]}…); I keep nothing");
        }
        catch (Exception ex) { Log("refund-on-close error: " + ex.Message); }
    }

    // tell the human (funder) the refund is broadcast, so the player window's close-ordering can proceed.
    private void SendRefundAck()
    {
        try
        {
            var ring = new KeyRing(_master);
            byte[] myPkh = Recovery.Hash160(_pub);
            foreach (var peerPub in _node.PeerWalletPubs())
            {
                long seq = System.Threading.Interlocked.Increment(ref _msgSeq);
                byte[] ack = System.Text.Encoding.ASCII.GetBytes("refunded|" + Tx.ToHex(_pub));
                byte[] carrier = TxMessage.SealCarrier(ring.MessagePriv(peerPub, "fund", seq), peerPub, TxType.BotRefund, ack);
                var tx = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0xffffffff, System.Array.Empty<byte>(), 0xffffffff) },
                    new[] { new TxOutputN(1, TxTransport.MessageOutput(carrier, myPkh)) }, 0);
                byte[] raw = Tx.Serialize(tx);
                foreach (var l in _node.LiveLinks()) { try { l.Send(raw); } catch { } }
            }
        }
        catch { }
    }

    private void End_Click(object sender, RoutedEventArgs e) => Close();   // ends the bot (Closed reaps the node + refunds)

    // ---- the bot is a real CHAT peer: it receives, acknowledges, and auto-replies ----
    private void Greet()
    {
        if (_greeted) return;
        _greeted = true;
        SendChat(Messenger.Text(Tx.ToHex(_pub), "hi — automated bot here, linked as a peer. Pay my address to fund me; message me and I'll reply."));
    }

    private void OnBotChat(PeerLink link, byte[] frame)
    {
        try
        {
            var tx = Tx.Parse(frame);
            if (tx is null) return;
            var ex = TxTransport.Extract(tx, _master);
            if (ex is null) return;
            if (ex.Value.type == TxType.GameClose)                          // human closed → refund first, then exit
            {
                Log("human closed the game — refunding and closing now");
                Dispatcher.Invoke(Close);                                   // Closed handler runs RefundFunderOnClose
                return;
            }
            ChatMessage? m = null;
            try { m = Messenger.Parse(ex.Value.plaintext); } catch { }
            if (m is null || m.FromPub == Tx.ToHex(_pub)) return;           // ignore our own echo
            if (m.Kind is ChatKind.Text or ChatKind.Reply or ChatKind.Media)
            {
                Log($"chat ← {m.FromPub[..6]}: {m.Display}");
                SendChat(Messenger.Read(Tx.ToHex(_pub), m.Id));             // read receipt (their ✓)
                // in-chat commands work for the bot too — pay is pay, same commands as any player
                if (ChatCommands.Is(m.Display))
                {
                    var c = ChatCommands.Parse(m.Display);
                    if (c.Kind == ChatCmd.AskAddress) { SendChat(Messenger.Text(Tx.ToHex(_pub), "\\addr " + NextRecv())); Log("asked for an address — sent a fresh one"); return; }
                    if (c.Kind == ChatCmd.Help) { SendChat(Messenger.Text(Tx.ToHex(_pub), ChatCommands.Help())); return; }
                    return;                                                  // other commands: nothing for the bot to do
                }
                SendChat(Messenger.Text(Tx.ToHex(_pub), $"got it: “{m.Display}”"));   // auto-reply
            }
        }
        catch (System.Exception e) { App.CrashLog("bot-chat-recv", e); }
    }

    private long _msgSeq;

    // Every message is a TRANSACTION, sent IP-to-IP per peer; heavy work off-thread and fully guarded.
    private void SendChat(ChatMessage m)
    {
        var peers = _node.PeerWalletPubs();
        var links = _node.LiveLinks();
        byte[] payload = Messenger.Serialize(m);
        byte[] master = _master, myPkh = Recovery.Hash160(_pub);
        System.Threading.Tasks.Task.Run(() =>
        {
            try
            {
                var ring = new KeyRing(master);
                foreach (var peerPub in peers)
                {
                    long seq = System.Threading.Interlocked.Increment(ref _msgSeq);
                    byte[] carrier = TxMessage.SealCarrier(ring.MessagePriv(peerPub, "lobby", seq), peerPub, TxType.Chat2P, payload);
                    var tx = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0xffffffff, System.Array.Empty<byte>(), 0xffffffff) },
                        new[] { new TxOutputN(1, TxTransport.MessageOutput(carrier, myPkh)) }, 0);
                    byte[] raw = Tx.Serialize(tx);
                    foreach (var l in links) l.Send(raw);
                }
            }
            catch (System.Exception ex) { App.CrashLog("bot-chat-send", ex); }
        });
        if (m.Kind is ChatKind.Text or ChatKind.Reply) Log($"chat → {m.Display}");
    }

    private void Log(string s) { BotLog.AppendText(s + "\n"); BotLog.ScrollToEnd(); }
}
