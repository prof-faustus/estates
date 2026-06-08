// Estates.Core/ChatCommands.cs — in-chat commands available to ANY participant (player↔player AND
// player↔bot). Commands are backslash-prefixed and travel as ordinary (encrypted) chat messages, so
// both sides parse them transparently. The flow the user asked for: Alice asks Bob where to send
// (\address), Bob's client auto-generates a FRESH receive address and states it (\addr <address>), then
// Alice pays it (\pay <address> <amount>). \help lists everything. Parsing is total — never throws.
using System;

namespace Estates.Core;

public enum ChatCmd { None, Help, AskAddress, StateAddress, Pay, Request, Balance }

/// <summary>A parsed chat command. Address/Amount are filled where the command carries them.</summary>
public sealed record ChatCommand(ChatCmd Kind, string Address, long Amount, string Raw);

public static class ChatCommands
{
    public const string Prefix = "\\";

    /// <summary>True if the text is a command (leading backslash).</summary>
    public static bool Is(string? s) => !string.IsNullOrWhiteSpace(s) && s.TrimStart().StartsWith(Prefix, StringComparison.Ordinal);

    public static ChatCommand Parse(string? s)
    {
        if (s is null) return new(ChatCmd.None, "", 0, "");
        string t = s.Trim();
        var p = t.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (p.Length == 0) return new(ChatCmd.None, "", 0, t);
        switch (p[0].ToLowerInvariant())
        {
            case "\\help": case "\\?":
                return new(ChatCmd.Help, "", 0, t);
            case "\\address": case "\\addr?": case "\\where":          // ASK the peer for an address
                return new(ChatCmd.AskAddress, "", 0, t);
            case "\\addr": case "\\here":                              // STATE an address (Bob: "send here")
                return new(ChatCmd.StateAddress, p.Length > 1 ? p[1] : "", 0, t);
            case "\\pay": case "\\send":                               // \pay <address> <amount>
            {
                string addr = p.Length > 1 ? p[1] : "";
                long amt = p.Length > 2 && long.TryParse(p[2], out var a) ? a : 0;
                return new(ChatCmd.Pay, addr, amt, t);
            }
            case "\\request": case "\\invoice":                       // \request <amount>  (ask to be paid)
            {
                long amt = p.Length > 1 && long.TryParse(p[1], out var a) ? a : 0;
                return new(ChatCmd.Request, "", amt, t);
            }
            case "\\balance": case "\\bal":
                return new(ChatCmd.Balance, "", 0, t);
            default:
                return new(ChatCmd.None, "", 0, t);
        }
    }

    public static string Help() =>
        "commands — \\help: this list · \\address: ask the other party for a send address (they auto-generate a fresh one) · " +
        "\\addr <address>: state your address · \\pay <address> <amount-sat>: pay it (a real on-chain payment) · " +
        "\\request <amount-sat>: ask to be paid (I post a fresh address) · \\balance: show my balance";
}
