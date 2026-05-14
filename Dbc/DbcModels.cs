using System.Collections.Generic;
using System.Linq;

namespace PcapReplayer
{
    public sealed class DbcDatabase
    {
        public List<DbcMessage> Messages { get; } = new();
        public List<string> Warnings { get; } = new();
        public int MultiplexedSignalsSkipped { get; internal set; }
        public int MessageCount => Messages.Count;
        public int SignalCount  => Messages.Sum(m => m.Signals.Count);
    }

    public sealed class DbcMessage
    {
        public required uint RawId { get; init; }
        public required uint CanId { get; init; }
        public required bool IsExtended { get; init; }
        public required string Name { get; init; }
        public required byte Dlc { get; init; }
        public string? Transmitter { get; init; }
        public string? Comment { get; set; }
        public List<DbcSignal> Signals { get; } = new();
    }

    public sealed class DbcSignal
    {
        public required string Name { get; init; }
        public required int StartBit { get; init; }
        public required int Length { get; init; }
        public required bool IsLittleEndian { get; init; }
        public required bool IsSigned { get; init; }
        public required double Factor { get; init; }
        public required double Offset { get; init; }
        public required double Min { get; init; }
        public required double Max { get; init; }
        public string Unit { get; init; } = string.Empty;
        public string? Receiver { get; init; }
        public string? Comment { get; set; }
        public int? Spn { get; set; }
        public Dictionary<long, string>? ValueTable { get; set; }
    }
}
