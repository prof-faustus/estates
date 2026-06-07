using System.Security.Cryptography;
using System.Windows;
using System.Windows.Threading;
using Estates.Core;

namespace Estates.App;

/// <summary>
/// A FULLY AUTOMATED bot — not a person. Its own narrow amber console, docked to a screen corner,
/// never over the player window. The human can FUND it (Funds tab), watch its Log, and END it
/// (End bot). It never fakes a solo game; it plays its seat only inside a real, funded, on-chain
/// peer-to-peer game it has joined.
/// </summary>
public partial class BotWindow : Window
{
    private readonly P2PNode _node;
    private readonly byte[] _master = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _pub;                 // chat/identity pubkey (same scheme as the player client)
    private readonly StandaloneWallet _wallet;
    private readonly DispatcherTimer _poll = new();
    private bool _greeted;

    public BotWindow()
    {
        InitializeComponent();
        var wa = SystemParameters.WorkArea;
        Left = wa.Right - Width - 12;
        Top = wa.Bottom - Height - 12;

        _pub = Cipher.PublicKey(_master);          // IDENTICAL scheme to MainWindow so chat keys match
        _node = new P2PNode("bot-" + Tx.ToHex(_pub)[..6], Tx.ToHex(_pub));
        _wallet = new StandaloneWallet(_master, "regtest");
        // Receive chat on every link. (Greeting is sent from the poll tick once we actually hold a
        // peer's key — the announce can arrive a moment after the socket links.)
        _node.OnLink += link => link.OnFrame += (l, f) => Dispatcher.Invoke(() => OnBotChat(l, f));
        App.Teardowns.Add(() => { try { _node.Dispose(); } catch { } });
        Closed += (_, _) => { _poll.Stop(); try { _node.Dispose(); } catch { } };

        ShowWallet();
        Log("automated bot started — connected as a peer node");
        Log("fund me (Funds tab), then I join a real on-chain game and play my seat");
        Log("I never simulate a solo game");

        _poll.Interval = TimeSpan.FromMilliseconds(2000);
        _poll.Tick += (_, _) =>
        {
            ShowWallet();
            BotStatus.Text = $"Connected · peers {_node.Peers().Count} · funded {_wallet.Balance()} sat";
            if (!_greeted && _node.LiveLinks().Count > 0 && _node.PeerWalletPubs().Count > 0) Greet();
        };
        _poll.Start();
        BotStatus.Text = "Connected · awaiting a real game";
    }

    private void ShowWallet() => BotWallet.Text = $"wallet {_wallet.AddressAt(0)}\nbalance {_wallet.Balance()} sat";

    private void Fund_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _wallet.AddCoin(FundTxid.Text.Trim(), long.Parse(FundVout.Text.Trim()), long.Parse(FundSat.Text.Trim()), 0);
            FundMsg.Text = $"imported · balance {_wallet.Balance()} sat";
            ShowWallet();
            Log($"funded: +{FundSat.Text.Trim()} sat");
        }
        catch (Exception ex) { FundMsg.Text = ex.Message; }
    }

    private void End_Click(object sender, RoutedEventArgs e) => Close();   // ends the bot (Closed reaps the node)

    // ---- the bot is a real CHAT peer: it receives, acknowledges, and auto-replies ----
    private void Greet()
    {
        if (_greeted) return;
        _greeted = true;
        SendChat(Messenger.Text(Tx.ToHex(_pub), "hi — automated bot here, linked as a peer. Message me and I'll reply."));
    }

    private void OnBotChat(PeerLink link, byte[] frame)
    {
        try
        {
            var tx = Tx.Parse(frame);
            if (tx is null) return;
            var ex = TxTransport.Extract(tx, _master);
            if (ex is null) return;
            ChatMessage? m = null;
            try { m = Messenger.Parse(ex.Value.plaintext); } catch { }
            if (m is null || m.FromPub == Tx.ToHex(_pub)) return;           // ignore our own echo
            if (m.Kind is ChatKind.Text or ChatKind.Reply or ChatKind.Media)
            {
                Log($"chat ← {m.FromPub[..6]}: {m.Display}");
                SendChat(Messenger.Read(Tx.ToHex(_pub), m.Id));             // read receipt (their ✓)
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
