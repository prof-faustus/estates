using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Estates.Core;

namespace Estates.App;

/// <summary>
/// A FULLY AUTOMATED bot — not a person. It starts its own game and plays itself on a timer. It is
/// deliberately UNLIKE the player window (narrow amber console, docked to a screen corner, never on
/// top, never the same size or look), and it can NEVER start another bot (no recursion). The human
/// who launched it (lobby → "Run a bot") may intervene — watch its wallet, take a move for it with
/// the buttons, toggle auto-play, or close the window to stop it — but it remains an automated bot.
/// Standalone: its own in-process node + wallet, no node/RPC/network dependency.
/// </summary>
public partial class BotWindow : Window
{
    private readonly P2PNode _node;
    private readonly byte[] _master = RandomNumberGenerator.GetBytes(32);
    private readonly StandaloneWallet _wallet;
    private GameState _game = null!;
    private readonly DispatcherTimer _timer = new();

    public BotWindow()
    {
        InitializeComponent();
        // dock to the BOTTOM-RIGHT corner of the work area — clearly separate from the centered
        // player window, never over it.
        var wa = SystemParameters.WorkArea;
        Left = wa.Right - Width - 12;
        Top = wa.Bottom - Height - 12;

        byte[] pub = Type42.PublicKey(_master);
        _node = new P2PNode("bot-" + Tx.ToHex(pub)[..6], Tx.ToHex(pub));
        _wallet = new StandaloneWallet(_master, "regtest");
        App.Teardowns.Add(() => { try { _node.Dispose(); } catch { } });
        Closed += (_, _) => { _timer.Stop(); try { _node.Dispose(); } catch { } };

        var deck = new Dictionary<string, List<int>>();
        foreach (var kv in Params.Instance.Decks) deck[kv.Key] = Enumerable.Range(0, kv.Value.Count).ToList();
        _game = Engine.InitialState("regtest", 2, 1_000_000, deck, false);   // the bot starts its OWN game

        ShowWallet();
        Render();
        _timer.Interval = TimeSpan.FromMilliseconds(1500);
        _timer.Tick += (_, _) => { if (AutoToggle.IsChecked == true) StepAuto(); };
        _timer.Start();
    }

    private void ShowWallet() => BotWallet.Text = $"wallet {_wallet.AddressAt(0)}\nbalance {_wallet.Balance()} sat";

    // The bot's automatic policy: take the next legal action with no human input.
    private void StepAuto()
    {
        var legal = Engine.LegalActions(_game);
        if (_game.Winner is not null || legal.Count == 0) return;
        string t = legal.Contains("ROLL") ? "ROLL" : legal.Contains("BUY") ? "BUY"
                 : legal.Contains("PAY_TAX") ? "PAY_TAX" : legal.Contains("END_TURN") ? "END_TURN" : legal[0];
        Apply(t, automated: true);
    }

    // Render the move buttons the HUMAN can press to take a move for the bot (intervention).
    private void Render()
    {
        BotMoves.Children.Clear();
        if (_game.Winner is not null) { BotStatus.Text = $"Game over — seat {_game.Winner} wins. Bot idle."; _timer.Stop(); return; }
        BotStatus.Text = $"seat {_game.Current}'s turn · turn {_game.TurnIndex}";
        foreach (var a in Engine.LegalActions(_game))
        {
            if (a is not ("ROLL" or "BUY" or "DECLINE" or "PAY_TAX" or "END_TURN" or "FORFEIT")) continue;
            var b = new Button { Content = a, Margin = new Thickness(2), FontSize = 11, Padding = new Thickness(6, 2, 6, 2) };
            string act = a; b.Click += (_, _) => Apply(act, automated: false);
            BotMoves.Children.Add(b);
        }
    }

    private void Apply(string type, bool automated)
    {
        var legal = Engine.LegalActions(_game);
        if (!legal.Contains(type)) return;
        Estates.Core.Action a = type switch
        {
            "ROLL" => new Estates.Core.Action("ROLL") { Dice = new[] { RandomNumberGenerator.GetInt32(1, 7), RandomNumberGenerator.GetInt32(1, 7) } },
            "PAY_TAX" => new Estates.Core.Action("PAY_TAX") { Choice = "flat" },
            _ => new Estates.Core.Action(type),
        };
        var res = Engine.Apply(_game, a);
        if (res.Ok && res.State is not null)
        {
            _game = res.State;
            Log($"{(automated ? "auto" : "you ")} · seat {_game.Current}: {type}");
        }
        else Log($"{type} rejected: {res.Code}");
        ShowWallet();
        Render();
    }

    private void Log(string s) { BotLog.AppendText(s + "\n"); BotLog.ScrollToEnd(); }
}
