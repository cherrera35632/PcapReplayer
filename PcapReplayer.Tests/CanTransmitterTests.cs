using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    [TestClass]
    public class CanTransmitterTests
    {
        [TestMethod]
        public async Task StartAsync_One10MsMessage_YieldsApproximately100PacketsPerSecond()
        {
            var sink = new CapturedUdpSink();
            var tx   = new CanTransmitter(sink);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));

            await tx.StartAsync(CreateConfig(CreateMessage(10)), cts.Token);

            Assert.IsTrue(sink.Packets.Count >= 95 && sink.Packets.Count <= 105,
                $"Expected about 100 packets, saw {sink.Packets.Count}.");
        }

        [TestMethod]
        public async Task StartAsync_MutedSignal_ContributesZeroBitsToPayload()
        {
            var sink = new CapturedUdpSink();
            var tx   = new CanTransmitter(sink);
            var message = CreateMessage(20,
                CreateSignalState(raw: 0xAB, muted: true, startBit: 0, length: 8, littleEndian: true));
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(40));

            await tx.StartAsync(CreateConfig(message), cts.Token);

            Assert.IsTrue(sink.Packets.Count > 0);
            byte[] frame = sink.Packets[0].Skip(HeaderBytes.Length).Take(13).ToArray();
            CollectionAssert.AreEqual(new byte[8], frame.Skip(5).Take(8).ToArray());
        }

        [TestMethod]
        public async Task StopAndCancellation_StopLoopWithin50Milliseconds()
        {
            var sink = new CapturedUdpSink();
            var tx   = new CanTransmitter(sink);
            using var cts = new CancellationTokenSource();

            Task run = tx.StartAsync(CreateConfig(CreateMessage(1000)), cts.Token);
            await Task.Delay(20);

            var sw = Stopwatch.StartNew();
            tx.Stop();
            cts.Cancel();
            await run;
            sw.Stop();

            Assert.IsTrue(sw.ElapsedMilliseconds < 50, $"Cancellation took {sw.ElapsedMilliseconds} ms.");
        }

        [TestMethod]
        public async Task StartAsync_MessagesDueSameTick_BatchesIntoSinglePacket()
        {
            var sink = new CapturedUdpSink();
            var tx   = new CanTransmitter(sink);
            using var cts = new CancellationTokenSource();
            Task run = tx.StartAsync(CreateConfig(CreateMessage(50), CreateMessage(50)), cts.Token);

            await Task.Delay(20);
            tx.Stop();
            cts.Cancel();
            await run;

            Assert.IsTrue(sink.Packets.Count >= 1);
            Assert.AreEqual(HeaderBytes.Length + 26, sink.Packets[0].Length);
        }

        private static readonly byte[] HeaderBytes = System.Text.Encoding.ASCII.GetBytes("ASSET|Type|Mfg|Db|CAN1");

        private static CanGenConfig CreateConfig(params MessageTxState[] messages)
            => new("127.0.0.1", 35251, "127.0.0.1", System.Text.Encoding.ASCII.GetString(HeaderBytes), messages);

        private static MessageTxState CreateMessage(int periodMs, params SignalTxState[] signals)
        {
            var message = new MessageTxState
            {
                Name       = "Msg",
                CanId      = 0x18FECAFE,
                IsExtended = true,
                Dlc        = 8,
                Enabled    = true,
                PeriodMs   = periodMs
            };
            foreach (var signal in signals) message.Signals.Add(signal);
            return message;
        }

        private static SignalTxState CreateSignalState(long raw, bool muted, int startBit, int length, bool littleEndian)
            => new()
            {
                Signal = new DbcSignal
                {
                    Name           = "Sig",
                    StartBit       = startBit,
                    Length         = length,
                    IsLittleEndian = littleEndian,
                    IsSigned       = false,
                    Factor         = 1,
                    Offset         = 0,
                    Min            = 0,
                    Max            = 255,
                    Unit           = string.Empty
                },
                RawValue      = raw,
                PhysicalValue = raw,
                IsMuted       = muted,
                Error         = null
            };

        private sealed class CapturedUdpSink : IUdpSink
        {
            private readonly object _gate = new();
            public List<byte[]> Packets { get; } = new();
            public List<IPEndPoint> Targets { get; } = new();

            public void Send(byte[] buffer, int length, IPEndPoint target)
            {
                var copy = new byte[length];
                Buffer.BlockCopy(buffer, 0, copy, 0, length);
                lock (_gate)
                {
                    Packets.Add(copy);
                    Targets.Add(target);
                }
            }
        }
    }
}
