using System.Collections.Generic;

namespace PcapReplayer
{
    public sealed class MessageTxState
    {
        public required string Name { get; init; }
        public uint CanId { get; init; }
        public bool IsExtended { get; init; }
        public byte Dlc { get; init; }
        public int PeriodMs { get; set; } = 100;
        public bool Enabled { get; set; } = true;
        public byte[] Data { get; } = new byte[8];
        public List<SignalTxState> Signals { get; } = new();
        public long NextSendTs { get; set; }
        public string? Comment { get; init; }
    }

    public sealed class SignalTxState
    {
        public required DbcSignal Signal { get; init; }
        public bool IsMuted { get; set; }
        public double PhysicalValue { get; set; }
        public long RawValue { get; set; }
        public string? Error { get; set; }
    }
}
