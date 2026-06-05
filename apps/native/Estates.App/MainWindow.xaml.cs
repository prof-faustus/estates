using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Estates.Core;
using GameAction = Estates.Core.Action;

namespace Estates.App;

public partial class MainWindow : Window
{
    private static readonly Dictionary<string, string> GroupColor = new()
    {
        ["Sienna"] = "#8d5524", ["Sky"] = "#aee1f9", ["Rose"] = "#f7a8c4", ["Amber"] = "#f5a623",
        ["Crimson"] = "#d0021b", ["Gold"] = "#f8e71c", ["Viridian"] = "#2e7d32", ["Indigo"] = "#283593",
        ["Rails"] = "#888", ["Utilities"] = "#bbb",
    };

    public MainWindow()
    {
        InitializeComponent();
        try
        {
            var p = Params.Instance;
            BuildBoard(p);
            // prove the validated core loaded: show the params version + a quick engine self-check.
            var s = Engine.InitialState("regtest", 2, 1_000_000);
            CoreStatus.Text = $"core loaded ✓  params {p.ParamsVersion}  · board {p.Board.Count} spaces · engine hash {Canonical.HashState(s)[..12]}…";
        }
        catch (Exception ex) { CoreStatus.Text = "core error: " + ex.Message; }
    }

    private void BuildBoard(Params p)
    {
        foreach (var sp in p.Board)
        {
            var bar = new Border { Height = 6, Background = Brush(sp.Group != null && GroupColor.TryGetValue(sp.Group, out var c) ? c : "#3a3d42") };
            var name = new TextBlock { Text = sp.Name, Foreground = Brush("#e6e6e6"), FontWeight = FontWeights.SemiBold, FontSize = 12, TextWrapping = TextWrapping.Wrap };
            var sub = new TextBlock { Foreground = Brush("#9aa0a6"), FontSize = 10, Margin = new Thickness(0, 2, 0, 0),
                Text = sp.BasePrice is long bp ? $"{sp.Type} · {bp} sat" : sp.Type };
            var stack = new StackPanel();
            stack.Children.Add(bar); stack.Children.Add(name); stack.Children.Add(sub);
            BoardList.Items.Add(new Border
            {
                Width = 118, Height = 78, Margin = new Thickness(5), Padding = new Thickness(7),
                CornerRadius = new CornerRadius(6), Background = Brush("#232529"), Child = stack,
            });
        }
    }

    private static SolidColorBrush Brush(string hex) => new((Color)ColorConverter.ConvertFromString(hex));

    private void Play_Click(object sender, RoutedEventArgs e)
    {
        int seats = int.Parse(((ComboBoxItem)SeatCount.SelectedItem).Content.ToString()!);
        var log = new StringBuilder();
        try
        {
            var s = Engine.InitialState("regtest", seats, 1_000_000);
            int step = 0; uint rng = 0xC0FFEE;
            // unbiased demo die (rejection sampling; reject bytes >= 252) — the same
            // standard the real beacon uses. A live game's dice come from the beacon.
            int Die() { for (; ; ) { rng = rng * 1103515245 + 12345; int b = (int)(rng & 0xff); if (b < 252) return (b % 6) + 1; } }

            while (s.Phase != "GAME_OVER" && step < 4000 && s.TurnIndex <= 80)
            {
                GameAction a = s.Phase switch
                {
                    "AWAIT_ROLL" => new GameAction("ROLL") { Dice = new[] { Die(), Die() } },
                    "AWAIT_BUY" => s.Seats[s.Current].Balance > 600 ? new GameAction("BUY") : new GameAction("DECLINE"),
                    "AWAIT_TAX" => new GameAction("PAY_TAX") { Choice = "flat" },
                    _ => new GameAction("END_TURN"),
                };
                var r = Engine.Apply(s, a);
                if (!r.Ok) { var r2 = Engine.Apply(s, new GameAction("END_TURN")); if (!r2.Ok) break; s = r2.State!; continue; }
                s = r.State!;
                if (s.Log.Count > 0 && step % 1 == 0) log.AppendLine($"t{s.TurnIndex,-3} {s.Log[^1]}");
                step++;
            }

            var alive = s.Seats.Where(x => !x.Bankrupt).ToList();
            long total = s.Seats.Sum(x => x.Balance) + s.BankReserve;
            ResultLine.Text = $"{step} moves · phase {s.Phase} · winner {(s.Winner?.ToString() ?? "—")} · sats conserved: {total:N0} · state {Canonical.HashState(s)[..12]}…";
            LogBox.Text = log.ToString();
            LogBox.ScrollToEnd();
        }
        catch (Exception ex) { ResultLine.Text = "error: " + ex.Message; }
    }
}
