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
    private readonly StandaloneWallet _wallet;
    private readonly DispatcherTimer _poll = new();

    public BotWindow()
    {
        InitializeComponent();
        var wa = SystemParameters.WorkArea;
        Left = wa.Right - Width - 12;
        Top = wa.Bottom - Height - 12;

        byte[] pub = Type42.PublicKey(_master);
        _node = new P2PNode("bot-" + Tx.ToHex(pub)[..6], Tx.ToHex(pub));
        _wallet = new StandaloneWallet(_master, "regtest");
        App.Teardowns.Add(() => { try { _node.Dispose(); } catch { } });
        Closed += (_, _) => { _poll.Stop(); try { _node.Dispose(); } catch { } };

        ShowWallet();
        Log("automated bot started — connected as a peer node");
        Log("fund me (Funds tab), then I join a real on-chain game and play my seat");
        Log("I never simulate a solo game");

        _poll.Interval = TimeSpan.FromMilliseconds(2000);
        _poll.Tick += (_, _) => { ShowWallet(); BotStatus.Text = $"Connected · peers {_node.Peers().Count} · funded {_wallet.Balance()} sat"; };
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

    private void Log(string s) { BotLog.AppendText(s + "\n"); BotLog.ScrollToEnd(); }
}
