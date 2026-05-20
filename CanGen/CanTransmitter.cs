using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PcapReplayer
{
    public sealed class CanTransmitter : ICanTransmitter
    {
        private const double SpinThresholdMs = 1.5;
        private static readonly double TicksPerMs = Stopwatch.Frequency / 1000.0;
        private readonly IUdpSink? _testSink;
        private volatile bool _stopRequested;

        public CanTransmitter()
        {
        }

        internal CanTransmitter(IUdpSink? sink)
        {
            _testSink = sink;
        }

        public event Action<string>? OnLog;
        public event Action<int>? OnTxCount;
        public event Action<Exception>? OnError;

        public void Stop() => _stopRequested = true;

        public async Task StartAsync(CanGenConfig cfg, CancellationToken ct)
        {
            _stopRequested = false;

            try
            {
                await Task.Run(() => RunCore(cfg, ct), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                OnLog?.Invoke("CAN TX stopped.");
            }
            catch (Exception ex)
            {
                OnError?.Invoke(ex);
            }
        }

        private void RunCore(CanGenConfig cfg, CancellationToken ct)
        {
            if (string.IsNullOrWhiteSpace(cfg.UsrMetadataHeader))
                throw new ArgumentException("USR metadata header is required.", nameof(cfg));
            if (cfg.UsrMetadataHeader.Length > 40)
                throw new ArgumentException("USR metadata header cannot exceed 40 characters.", nameof(cfg));
            if (cfg.TargetPort < 1 || cfg.TargetPort > 65535)
                throw new ArgumentException("Target port must be between 1 and 65535.", nameof(cfg));

            IReadOnlyList<MessageTxState> allMessages = cfg.Messages;

            byte[] headerBytes = Encoding.ASCII.GetBytes(cfg.UsrMetadataHeader);
            long now    = Stopwatch.GetTimestamp();
            long startTs = now; // anchor for sine elapsed-time computation
            foreach (var message in allMessages)
            {
                message.NextSendTs = now;
                if (message.MultiplexGroups != null)
                {
                    foreach (var group in message.MultiplexGroups.Values)
                        group.NextSendTs = now;
                }
            }

            var target = new IPEndPoint(IPAddress.Parse(cfg.TargetIp), cfg.TargetPort);
            IUdpSink sink = _testSink ?? new UdpClientSink(cfg.SourceIp);
            bool ownsSink = _testSink == null;
            int totalFrames = 0;
            long batchWindowTicks = (long)TicksPerMs;

            try
            {
                OnLog?.Invoke($"CAN TX starting: {allMessages.Count} messages → {cfg.TargetIp}:{cfg.TargetPort}");

                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    ThrowIfStopRequested();

                    // Collect all schedulable items: non-mux messages use message.NextSendTs,
                    // mux messages use per-group NextSendTs for each enabled group.
                    long nextDue = long.MaxValue;
                    bool anyEnabled = false;

                    foreach (var message in allMessages)
                    {
                        if (!message.Enabled) continue;

                        if (message.IsMultiplexed && message.MultiplexGroups != null)
                        {
                            foreach (var group in message.MultiplexGroups.Values)
                            {
                                if (!group.Enabled) continue;
                                anyEnabled = true;
                                if (group.NextSendTs < nextDue) nextDue = group.NextSendTs;
                            }
                        }
                        else
                        {
                            anyEnabled = true;
                            if (message.NextSendTs < nextDue) nextDue = message.NextSendTs;
                        }
                    }

                    if (!anyEnabled)
                    {
                        Thread.Sleep(10);
                        continue;
                    }

                    WaitUntil(nextDue, ct);

                    long dueCutoff = Stopwatch.GetTimestamp() + batchWindowTicks;
                    double elapsedSec = (Stopwatch.GetTimestamp() - startTs) / (double)Stopwatch.Frequency;

                    // Build frames for all due items
                    var frames = new List<byte[]>();
                    foreach (var message in allMessages)
                    {
                        if (!message.Enabled) continue;

                        if (message.IsMultiplexed && message.MultiplexGroups != null)
                        {
                            foreach (var group in message.MultiplexGroups.Values)
                            {
                                if (!group.Enabled) continue;
                                if (group.NextSendTs > dueCutoff) continue;
                                // Update non-muxed normal signals
                                foreach (var sig in message.Signals)
                                    if (sig.Signal.MultiplexIndicator == null)
                                        SignalValueGenerator.Update(sig, elapsedSec);
                                // Update the group's own signals
                                foreach (var sig in group.Signals)
                                    SignalValueGenerator.Update(sig, elapsedSec);
                                frames.Add(UsrFrameBuilder.Build13BytesForMuxGroup(message, group.MuxValue));
                                group.NextSendTs += (long)(group.PeriodMs * TicksPerMs);
                            }
                        }
                        else
                        {
                            if (message.NextSendTs > dueCutoff) continue;
                            foreach (var sig in message.Signals)
                                SignalValueGenerator.Update(sig, elapsedSec);
                            frames.Add(UsrFrameBuilder.Build13Bytes(message));
                            message.NextSendTs += (long)(message.PeriodMs * TicksPerMs);
                        }
                    }

                    if (frames.Count == 0)
                        continue;

                    byte[] packet = BuildPacketFromFrames(headerBytes, frames);
                    sink.Send(packet, packet.Length, target);

                    totalFrames += frames.Count;
                    OnTxCount?.Invoke(totalFrames);
                }
            }
            finally
            {
                if (ownsSink && sink is IDisposable disposable)
                    disposable.Dispose();
            }
        }

        private static byte[] BuildPacketFromFrames(byte[] headerBytes, IReadOnlyList<byte[]> frames)
        {
            var packet = new byte[headerBytes.Length + frames.Count * UsrPacketHelper.USR_FRAME_SIZE];
            Buffer.BlockCopy(headerBytes, 0, packet, 0, headerBytes.Length);

            int offset = headerBytes.Length;
            foreach (var frame in frames)
            {
                Buffer.BlockCopy(frame, 0, packet, offset, frame.Length);
                offset += frame.Length;
            }

            return packet;
        }

        private static void WaitUntil(long targetTimestamp, CancellationToken ct)
        {
            while (Stopwatch.GetTimestamp() < targetTimestamp)
            {
                ct.ThrowIfCancellationRequested();

                long remainingTicks = targetTimestamp - Stopwatch.GetTimestamp();
                double remainingMs = remainingTicks / TicksPerMs;
                if (remainingMs > SpinThresholdMs)
                {
                    int sleepMs = (int)Math.Floor(remainingMs - SpinThresholdMs);
                    if (sleepMs > 0)
                    {
                        Thread.Sleep(Math.Min(sleepMs, 10));
                        continue;
                    }
                }

                Thread.SpinWait(50);
            }
        }

        private void ThrowIfStopRequested()
        {
            if (_stopRequested)
                throw new OperationCanceledException();
        }
    }

    internal interface IUdpSink
    {
        void Send(byte[] buffer, int length, IPEndPoint target);
    }

    internal sealed class UdpClientSink : IUdpSink, IDisposable
    {
        private readonly UdpClient _client;

        public UdpClientSink(string sourceIp)
        {
            _client = new UdpClient(new IPEndPoint(IPAddress.Parse(sourceIp), 0));
            _client.Client.SendBufferSize = 65536;
        }

        public void Send(byte[] buffer, int length, IPEndPoint target)
            => _client.Client.SendTo(buffer, 0, length, SocketFlags.None, target);

        public void Dispose() => _client.Dispose();
    }
}
