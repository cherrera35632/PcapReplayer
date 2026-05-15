using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace PcapReplayer
{
    public static class DbcParser
    {
        private static readonly Regex BoPattern = new(
            "^BO_\\s+(\\d+)\\s+(\\S+)\\s*:\\s*(\\d+)\\s*(\\S+)?",
            RegexOptions.Compiled);

        private static readonly Regex SignalPattern = new(
            "^(\\d+)\\|(\\d+)@([01])([+-])\\s+\\(([-+0-9.eE]+),([-+0-9.eE]+)\\)\\s+\\[([-+0-9.eE]+)\\|([-+0-9.eE]+)\\]\\s+\"([^\"]*)\"(?:\\s+(.*))?$",
            RegexOptions.Compiled);

        private static readonly Regex MessageCommentPattern = new(
            "^CM_\\s+BO_\\s+(\\d+)\\s+\"((?:\\\\.|[^\"])*)\";",
            RegexOptions.Compiled);

        private static readonly Regex SignalCommentPattern = new(
            "^CM_\\s+SG_\\s+(\\d+)\\s+(\\S+)\\s+\"((?:\\\\.|[^\"])*)\";",
            RegexOptions.Compiled);

        private static readonly Regex ValueEntryPattern = new(
            "(-?\\d+)\\s+\"([^\"]*)\"",
            RegexOptions.Compiled);

        private static readonly Regex SpnPattern = new(
            "\\bSPN\\D*(\\d+)\\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public static DbcDatabase ParseFile(string path)
            => Parse(File.ReadAllText(path));

        public static DbcDatabase Parse(string dbcText)
        {
            var db              = new DbcDatabase();
            var messagesByRawId = new Dictionary<uint, DbcMessage>();
            DbcMessage? current = null;

            using var reader = new StringReader(dbcText ?? string.Empty);
            string? line;
            int lineNumber = 0;

            while ((line = reader.ReadLine()) != null)
            {
                lineNumber++;
                string trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                if (trimmed.StartsWith("BO_ ", StringComparison.Ordinal))
                {
                    current = ParseMessage(trimmed, lineNumber, db);
                    if (current != null)
                    {
                        db.Messages.Add(current);
                        messagesByRawId[current.RawId] = current;
                    }
                    continue;
                }

                if (trimmed.StartsWith("SG_ ", StringComparison.Ordinal))
                {
                    if (current == null) continue;
                    if (TryParseSignal(trimmed, lineNumber, db, out var signal))
                        current.Signals.Add(signal);
                    continue;
                }

                if (trimmed.StartsWith("CM_ ", StringComparison.Ordinal))
                {
                    ApplyComment(trimmed, messagesByRawId);
                    continue;
                }

                if (trimmed.StartsWith("VAL_ ", StringComparison.Ordinal))
                    ApplyValueTable(trimmed, messagesByRawId);
            }

            return db;
        }

        private static DbcMessage? ParseMessage(string line, int lineNumber, DbcDatabase db)
        {
            var match = BoPattern.Match(line);
            if (!match.Success)
            {
                db.Warnings.Add($"Line {lineNumber}: could not parse message declaration.");
                return null;
            }

            uint rawId = uint.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
            bool isExtended = (rawId & 0x80000000u) != 0;
            uint canId = isExtended ? (rawId & 0x1FFFFFFFu) : rawId;

            return new DbcMessage
            {
                RawId       = rawId,
                CanId       = canId,
                IsExtended  = isExtended,
                Name        = match.Groups[2].Value,
                Dlc         = byte.Parse(match.Groups[3].Value, CultureInfo.InvariantCulture),
                Transmitter = match.Groups[4].Success ? match.Groups[4].Value : null
            };
        }

        private static bool TryParseSignal(string line, int lineNumber, DbcDatabase db, out DbcSignal signal)
        {
            signal = null!;
            string body = line.Substring(3).Trim();
            int colonIndex = body.IndexOf(':');
            if (colonIndex < 0)
            {
                db.Warnings.Add($"Line {lineNumber}: could not parse signal declaration.");
                return false;
            }

            string left  = body[..colonIndex].Trim();
            string right = body[(colonIndex + 1)..].Trim();
            string[] leftParts = left.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (leftParts.Length == 0)
            {
                db.Warnings.Add($"Line {lineNumber}: signal missing a name.");
                return false;
            }

            // Detect multiplex indicator from tokens after the signal name
            string? muxIndicator = null;
            foreach (var token in leftParts.Skip(1))
            {
                if (token.Equals("M", StringComparison.Ordinal))
                {
                    muxIndicator = "M";
                    break;
                }
                if (token.Length > 1 && (token[0] == 'm' || token[0] == 'M') && int.TryParse(token[1..], out _))
                {
                    // Normalize to lowercase "mN"
                    muxIndicator = "m" + token[1..];
                    break;
                }
            }

            var match = SignalPattern.Match(right);
            if (!match.Success)
            {
                db.Warnings.Add($"Line {lineNumber}: could not parse signal '{leftParts[0]}'.");
                return false;
            }

            signal = new DbcSignal
            {
                Name               = leftParts[0],
                StartBit           = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture),
                Length             = int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture),
                IsLittleEndian     = match.Groups[3].Value == "1",
                IsSigned           = match.Groups[4].Value == "-",
                Factor             = double.Parse(match.Groups[5].Value, CultureInfo.InvariantCulture),
                Offset             = double.Parse(match.Groups[6].Value, CultureInfo.InvariantCulture),
                Min                = double.Parse(match.Groups[7].Value, CultureInfo.InvariantCulture),
                Max                = double.Parse(match.Groups[8].Value, CultureInfo.InvariantCulture),
                Unit               = Unescape(match.Groups[9].Value),
                Receiver           = match.Groups[10].Success ? match.Groups[10].Value.Trim() : null,
                MultiplexIndicator = muxIndicator
            };

            return true;
        }

        private static void ApplyComment(string line, Dictionary<uint, DbcMessage> messagesByRawId)
        {
            var msgComment = MessageCommentPattern.Match(line);
            if (msgComment.Success)
            {
                uint rawId = uint.Parse(msgComment.Groups[1].Value, CultureInfo.InvariantCulture);
                if (messagesByRawId.TryGetValue(rawId, out var message))
                    message.Comment = Unescape(msgComment.Groups[2].Value);
                return;
            }

            var sigComment = SignalCommentPattern.Match(line);
            if (!sigComment.Success) return;

            uint rawSigId = uint.Parse(sigComment.Groups[1].Value, CultureInfo.InvariantCulture);
            if (!messagesByRawId.TryGetValue(rawSigId, out var owner)) return;

            string signalName = sigComment.Groups[2].Value;
            var signal = owner.Signals.FirstOrDefault(s => s.Name == signalName);
            if (signal == null) return;

            string comment = Unescape(sigComment.Groups[3].Value);
            signal.Comment = comment;

            var spnMatch = SpnPattern.Match(comment);
            if (spnMatch.Success && int.TryParse(spnMatch.Groups[1].Value, out int spn))
                signal.Spn = spn;
        }

        private static void ApplyValueTable(string line, Dictionary<uint, DbcMessage> messagesByRawId)
        {
            string[] parts = line.Split(' ', 4, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 4) return;
            if (!uint.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out uint rawId)) return;
            if (!messagesByRawId.TryGetValue(rawId, out var message)) return;

            var signal = message.Signals.FirstOrDefault(s => s.Name == parts[2]);
            if (signal == null) return;

            string valuePart = parts[3];
            if (valuePart.EndsWith(";", StringComparison.Ordinal))
                valuePart = valuePart[..^1];

            var table = new Dictionary<long, string>();
            foreach (Match match in ValueEntryPattern.Matches(valuePart))
            {
                long raw = long.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
                table[raw] = Unescape(match.Groups[2].Value);
            }

            if (table.Count > 0)
                signal.ValueTable = table;
        }

        private static bool IsMultiplexToken(string token)
            => token.Equals("M", StringComparison.OrdinalIgnoreCase) ||
               (token.Length > 1 && (token[0] == 'm' || token[0] == 'M') && int.TryParse(token[1..], out _));

        private static string Unescape(string text)
            => text.Replace("\\\"", "\"");
    }
}
