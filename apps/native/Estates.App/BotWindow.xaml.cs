using System.Security.Cryptography;
using System.Windows;
using System.Windows.Threading;
using Estates.Core;

namespace Estates.App;

/// <summary>
/// An AUTOMATED bot — not a person. Its own small, distinct window, positioned away from the
/// player so it never opens on top. It plays the game by itself on a timer (a bot policy). The
/// human launches it (estates.exe --bot) and closes it to stop it; no human steers its moves.
/// STANDALONE: its own in-process node + Type-42 key — no node, no RPC, no network.
/// </summary>
public partial class BotWindow : Window
{
    private readonly P2PNode _node;
    private readonly byte[] _master = RandomNumberGenerator.GetBytes(32);
    private GameState _game = null!;
    private readonly DispatcherTimer _timer = new();

    public BotWindow()
    {
        InitializeComponent();
        var rnd = new Random();
        Left = rnd.Next(20, 380); Top = rnd.Next(20, 320);   // never on top of the centered player window

        byte[] pub = Type42.PublicKey(_master);
        _node = new P2PNode("bot-" + Tx.ToHex(pub)[..6], Tx.ToHex(pub));
        App.Teardowns.Add(() => { try { _node.Dispose(); } catch { } });
        Closed += (_, _) => { _timer.Stop(); try { _node.Dispose(); } catch { } };

        var deck = new Dictionary<string, List<int>>();
        foreach (var kv in Params.Instance.Decks) deck[kv.Key] = Enumerable.Range(0, kv.Value.Count).ToList();
        _game = Engine.InitialState("regtest", 2, 1_000_000, deck, false);

        BotStatus.Text = "Automated bot running — it plays itself, standalone (no node).";
        _timer.Interval = TimeSpan.FromMilliseconds(1500);
        _timer.Tick += (_, _) => Step();
        _timer.Start();
    }

    // The bot's automatic policy: take the next legal action (no human input) and apply it locally.
    private void Step()
    {
        var g = _game;
        if (g.Winner is not null) { BotStatus.Text = $"Game over — seat {g.Winner} wins. Bot idle."; _timer.Stop(); return; }
        var legal = Engine.LegalActions(g);
        if (legal.Count == 0) { _timer.Stop(); return; }
        string t = legal.Contains("ROLL") ? "ROLL" : legal.Contains("BUY") ? "BUY"
                 : legal.Contains("PAY_TAX") ? "PAY_TAX" : legal.Contains("END_TURN") ? "END_TURN" : legal[0];
        Estates.Core.Action a = t switch
        {
            "ROLL" => new Estates.Core.Action("ROLL") { Dice = new[] { RandomNumberGenerator.GetInt32(1, 7), RandomNumberGenerator.GetInt32(1, 7) } },
            "PAY_TAX" => new Estates.Core.Action("PAY_TAX") { Choice = "flat" },
            _ => new Estates.Core.Action(t),
        };
        var res = Engine.Apply(g, a);
        if (res.Ok && res.State is not null)
        {
            _game = res.State;
            Log($"seat {g.Current}: {t}  (signed, applied; standalone)");
        }
        else Log($"{t} rejected: {res.Code}");
    }

    private void Log(string s) { BotLog.AppendText(s + "\n"); BotLog.ScrollToEnd(); }
}
