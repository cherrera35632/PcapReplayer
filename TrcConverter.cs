using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapReplayer
{
    // ── Options ──────────────────────────────────────────────────────────────

    /// <summary>
    /// All inputs required to convert a PCAN-View .trc file into a
    /// USR-CANET200-compatible .pcap file.
    /// </summary>
    public record TrcConversionOptions
    {
        /// <summary>Full path to the .trc file to read.</summary>
        public string TrcFile { get; init; } = string.Empty;

        /// <summary>Full path of the .pcap file to create.</summary>
        public string OutputPcap { get; init; } = string.Empty;

        /// <summary>
        /// Pipe-delimited USR-CANET200 identity string injected as the ASCII
        /// header of the first UDP packet.
        /// Format: AssetId|EquipType|Mfg|Database|CANName
        /// </summary>
        public string MetadataHeader { get; init; } = "DEVICE|Type|Mfg|DB|CAN_ONE";

        /// <summary>UDP destination port. Default: 35251.</summary>
        public int DestPort { get; init; } = 35251;

        /// <summary>Source IP written into the IP header. Default: 192.168.1.100.</summary>
        public string SourceIP { get; init; } = "192.168.1.100";

        /// <summary>Destination IP written into the IP header. Default: 192.168.1.1.</summary>
        public string DestIP { get; init; } = "192.168.1.1";

        /// <summary>
        /// Maximum number of CAN frames per UDP packet (also bounded by
        /// <see cref="BatchThresholdMs"/>).
        /// </summary>
        public int FramesPerPacket { get; init; } = 10;

        /// <summary>
        /// Maximum elapsed time (in milliseconds) within a single batch.
        /// When the next frame's timestamp exceeds this delta, the current
        /// batch is flushed as a new UDP packet.
        /// </summary>
        public double BatchThresholdMs { get; init; } = 5.0;
    }

    // ── Result ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Summary returned by <see cref="TrcConverter.Convert"/> after a
    /// successful conversion.
    /// </summary>
    public record TrcConversionResult
    {
        public int    FramesParsed   { get; init; }
        public int    PacketsWritten { get; init; }
        public long   FileBytes      { get; init; }
        public DateTime BaseTime     { get; init; }
        /// <summary>Non-fatal warnings (e.g. lines that could not be parsed).</summary>
        public IReadOnlyList<string> Warnings { get; init; } = Array.Empty<string>();
    }

    // ── Internal CAN frame type ───────────────────────────────────────────────

    public record TrcCanFrame(double TimeMs, uint ID29, bool IsExtended, int DLC, byte[] Data);

    // ── Converter ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Converts a PCAN-View .trc file into a USR-CANET200-compatible .pcap
    /// that can be replayed by the PcapReplayer Replay tab.
    ///
    /// This is a pure, static, UI-free engine — a port of the
    /// TrcToUsrPcap CLI tool (iot_edge_udpcangateway/Tools/TrcToUsrPcap).
    ///
    /// Wire format preserved exactly:
    ///   • PCAP global header: magic 0xA1B2C3D4, link-type 1 (Ethernet)
    ///   • Each packet: Ethernet (14) + IP (20) + UDP (8) + payload
    ///   • Payload: optional ASCII metadata header (first packet only)
    ///              + N × 13-byte USR-CANET200 binary frames
    ///
    /// USR frame layout (13 bytes, §2.2.4 of USR-CANET200 manual):
    ///   Byte 0:    Info  — bit7=EXT, bit6=RTR, bits5-4=0, bits3-0=DLC
    ///   Bytes 1-4: CAN ID big-endian (29-bit, upper 3 bits zero)
    ///   Bytes 5-12: Data (always 8 bytes, zero-padded)
    /// </summary>
    public static class TrcConverter
    {
        // Fixed UDP source port (arbitrary, matches CLI tool)
        private const int SrcPort = 50000;

        // Regex matching PCAN-View 1.1 data lines:
        // "     1)        23.6  Rx     18F140CA  8  01 1E 00 28 00 00 00 00"
        private static readonly Regex LinePattern =
            new(@"^\s*\d+\)\s+([\d.]+)\s+Rx\s+([0-9A-Fa-f]+)\s+(\d+)\s+(.+)$",
                RegexOptions.Compiled);

        private static readonly Regex StartTimePattern =
            new(@"\$STARTTIME=([\d.]+)", RegexOptions.Compiled);

        /// <summary>
        /// Performs the TRC → PCAP conversion synchronously.
        /// </summary>
        /// <param name="opts">Conversion parameters.</param>
        /// <param name="progress">
        /// Optional progress sink — receives human-readable status lines
        /// (suitable for direct display in a log control).
        /// </param>
        /// <exception cref="ArgumentException">
        /// Thrown when required option fields are null/empty.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the .trc file yields zero parseable CAN frames.
        /// </exception>
        public static TrcConversionResult Convert(
            TrcConversionOptions opts,
            IProgress<string>?   progress = null)
        {
            // ── Validate ──────────────────────────────────────────────────────
            if (string.IsNullOrWhiteSpace(opts.TrcFile))
                throw new ArgumentException("TrcFile must not be null or empty.", nameof(opts));
            if (string.IsNullOrWhiteSpace(opts.OutputPcap))
                throw new ArgumentException("OutputPcap must not be null or empty.", nameof(opts));

            // ── Parse .trc ────────────────────────────────────────────────────
            Report(progress, $"📂 Parsing {Path.GetFileName(opts.TrcFile)} ...");

            string trcContent = File.ReadAllText(opts.TrcFile);

            // Extract base time from $STARTTIME (OLE Automation Date)
            DateTime baseTime  = DateTime.UtcNow;
            var      stMatch   = StartTimePattern.Match(trcContent);
            if (stMatch.Success &&
                double.TryParse(stMatch.Groups[1].Value,
                    NumberStyles.Float, CultureInfo.InvariantCulture, out double oleDate))
            {
                baseTime = DateTime.FromOADate(oleDate);
            }

            var epoch           = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            double baseEpochSec = (baseTime.ToUniversalTime() - epoch).TotalSeconds;

            var     frames   = new List<TrcCanFrame>();
            var     warnings = new List<string>();
            int     lineNum  = 0;

            foreach (string line in File.ReadLines(opts.TrcFile))
            {
                lineNum++;
                var m = LinePattern.Match(line);
                if (!m.Success) continue;

                if (!double.TryParse(m.Groups[1].Value,
                        NumberStyles.Float, CultureInfo.InvariantCulture, out double timeMs))
                {
                    warnings.Add($"Line {lineNum}: could not parse timestamp \"{m.Groups[1].Value}\"");
                    continue;
                }

                if (!uint.TryParse(m.Groups[2].Value, NumberStyles.HexNumber,
                        CultureInfo.InvariantCulture, out uint id))
                {
                    warnings.Add($"Line {lineNum}: could not parse CAN ID \"{m.Groups[2].Value}\"");
                    continue;
                }

                if (!int.TryParse(m.Groups[3].Value, out int dlc) || dlc < 0 || dlc > 8)
                {
                    warnings.Add($"Line {lineNum}: invalid DLC \"{m.Groups[3].Value}\"");
                    continue;
                }

                bool   isExtended = id > 0x7FF;
                uint   id29       = id & 0x1FFFFFFF;
                byte[] data       = ParseDataBytes(m.Groups[4].Value.Trim(), dlc);

                frames.Add(new TrcCanFrame(timeMs, id29, isExtended, dlc, data));
            }

            Report(progress, $"✅ Parsed {frames.Count} CAN frames  ({warnings.Count} skipped lines)");

            if (frames.Count == 0)
                throw new InvalidOperationException(
                    "No valid CAN frames found in the .trc file. " +
                    "Ensure the file contains 'Rx' lines in PCAN-View 1.1 format.");

            // ── Build PCAP ────────────────────────────────────────────────────
            Report(progress, $"🔧 Building {Path.GetFileName(opts.OutputPcap)} ...");
            Report(progress, $"   Metadata : {opts.MetadataHeader}");
            Report(progress, $"   Source   : {opts.SourceIP}:{SrcPort} → {opts.DestIP}:{opts.DestPort}");
            Report(progress, $"   Batching : max {opts.FramesPerPacket} frames / {opts.BatchThresholdMs} ms");
            Report(progress, $"   Base time: {baseTime:u}");

            // Ensure output directory exists
            string? outDir = Path.GetDirectoryName(opts.OutputPcap);
            if (!string.IsNullOrEmpty(outDir))
                Directory.CreateDirectory(outDir);

            using var fs     = File.Create(opts.OutputPcap);
            using var writer = new BinaryWriter(fs);

            WritePcapGlobalHeader(writer);

            int    packetCount   = 0;
            bool   isFirstPacket = true;
            var    batch         = new List<TrcCanFrame>();
            double batchStartMs  = frames[0].TimeMs;

            for (int fi = 0; fi <= frames.Count; fi++)
            {
                bool       flush = fi == frames.Count;
                TrcCanFrame? f  = fi < frames.Count ? frames[fi] : null;

                if (!flush && batch.Count > 0)
                {
                    double delta = f!.TimeMs - batchStartMs;
                    if (delta > opts.BatchThresholdMs || batch.Count >= opts.FramesPerPacket)
                        flush = true;
                }

                if (flush && batch.Count > 0)
                {
                    using var payloadMs = new MemoryStream();

                    if (isFirstPacket && !string.IsNullOrEmpty(opts.MetadataHeader))
                    {
                        payloadMs.Write(Encoding.ASCII.GetBytes(opts.MetadataHeader));
                        isFirstPacket = false;
                    }

                    foreach (var bf in batch)
                        payloadMs.Write(BuildUsrFrame(bf));

                    byte[] payload   = payloadMs.ToArray();
                    double pktTimeSec = baseEpochSec + (batch[0].TimeMs / 1000.0);
                    byte[] udpPkt    = BuildUdpPacket(opts.SourceIP, opts.DestIP,
                                                       SrcPort, opts.DestPort, payload);
                    WritePcapPacket(writer, udpPkt, pktTimeSec);
                    packetCount++;

                    batch.Clear();
                    if (f != null) batchStartMs = f.TimeMs;
                }

                if (f != null) batch.Add(f);
            }

            writer.Flush();

            long fileBytes = new FileInfo(opts.OutputPcap).Length;
            Report(progress, $"✅ Written {packetCount} UDP packets  ({fileBytes:N0} bytes)");
            Report(progress, $"📄 Output : {opts.OutputPcap}");
            Report(progress, $"💡 Load in Replay tab to send to the gateway");

            return new TrcConversionResult
            {
                FramesParsed   = frames.Count,
                PacketsWritten = packetCount,
                FileBytes      = fileBytes,
                BaseTime       = baseTime,
                Warnings       = warnings
            };
        }

        // ── Public helpers (called from tests) ────────────────────────────────

        /// <summary>
        /// Builds the 13-byte USR-CANET200 binary frame for a single CAN frame.
        /// </summary>
        public static byte[] BuildUsrFrame(TrcCanFrame f)
        {
            byte info = (byte)(f.DLC & 0x0F);
            if (f.IsExtended) info |= 0x80;

            var frame = new byte[13];
            frame[0] = info;
            frame[1] = (byte)((f.ID29 >> 24) & 0xFF);
            frame[2] = (byte)((f.ID29 >> 16) & 0xFF);
            frame[3] = (byte)((f.ID29 >>  8) & 0xFF);
            frame[4] = (byte)( f.ID29        & 0xFF);
            Array.Copy(f.Data, 0, frame, 5, Math.Min(f.Data.Length, 8));
            return frame;
        }

        /// <summary>
        /// Writes the 24-byte PCAP global header to <paramref name="writer"/>.
        /// Link-type 1 = Ethernet.
        /// </summary>
        public static void WritePcapGlobalHeader(BinaryWriter writer)
        {
            writer.Write(0xA1B2C3D4u); // magic
            writer.Write((ushort)2);   // major version
            writer.Write((ushort)4);   // minor version
            writer.Write(0);           // GMT offset
            writer.Write(0u);          // sigfigs
            writer.Write(65535u);      // snaplen
            writer.Write(1u);          // link type: Ethernet
        }

        /// <summary>
        /// Builds a complete Ethernet + IPv4 + UDP packet byte array.
        /// </summary>
        public static byte[] BuildUdpPacket(
            string srcIP, string dstIP,
            int srcPort, int dstPort,
            byte[] payload)
        {
            int totalLen = 14 + 20 + 8 + payload.Length;
            var pkt      = new byte[totalLen];
            int off      = 0;

            // Ethernet header (14 bytes)
            for (int i = 0; i < 6; i++) pkt[off + i] = 0xFF; // dst MAC broadcast
            pkt[off + 6] = 0x00; pkt[off + 7] = 0x11; pkt[off + 8]  = 0x22;
            pkt[off + 9] = 0x33; pkt[off +10] = 0x44; pkt[off + 11] = 0x55;
            pkt[off +12] = 0x08; pkt[off +13] = 0x00; // EtherType IPv4
            off += 14;

            // IPv4 header (20 bytes)
            int ipLen = 20 + 8 + payload.Length;
            pkt[off + 0] = 0x45;                               // Ver=4, IHL=5
            pkt[off + 2] = (byte)((ipLen >> 8) & 0xFF);
            pkt[off + 3] = (byte)( ipLen       & 0xFF);
            pkt[off + 4] = 0x00; pkt[off + 5] = 0x01;         // Identification
            pkt[off + 8] = 0x40;                               // TTL=64
            pkt[off + 9] = 0x11;                               // Protocol=UDP
            var srcParts = srcIP.Split('.');
            var dstParts = dstIP.Split('.');
            for (int i = 0; i < 4; i++) pkt[off + 12 + i] = byte.Parse(srcParts[i]);
            for (int i = 0; i < 4; i++) pkt[off + 16 + i] = byte.Parse(dstParts[i]);
            off += 20;

            // UDP header (8 bytes)
            int udpLen = 8 + payload.Length;
            pkt[off + 0] = (byte)((srcPort >> 8) & 0xFF);
            pkt[off + 1] = (byte)( srcPort       & 0xFF);
            pkt[off + 2] = (byte)((dstPort >> 8) & 0xFF);
            pkt[off + 3] = (byte)( dstPort       & 0xFF);
            pkt[off + 4] = (byte)((udpLen  >> 8) & 0xFF);
            pkt[off + 5] = (byte)( udpLen        & 0xFF);
            off += 8;

            // Payload
            Array.Copy(payload, 0, pkt, off, payload.Length);
            return pkt;
        }

        /// <summary>
        /// Writes a single PCAP packet record to <paramref name="writer"/>.
        /// </summary>
        public static void WritePcapPacket(BinaryWriter writer, byte[] packet, double timestampSeconds)
        {
            uint tsSec  = (uint)Math.Floor(timestampSeconds);
            uint tsUsec = (uint)Math.Floor((timestampSeconds - tsSec) * 1_000_000);
            writer.Write(tsSec);
            writer.Write(tsUsec);
            writer.Write((uint)packet.Length);
            writer.Write((uint)packet.Length);
            writer.Write(packet);
        }

        // ── Private helpers ───────────────────────────────────────────────────

        private static byte[] ParseDataBytes(string dataStr, int dlc)
        {
            var    data  = new byte[8];
            string[] hex = dataStr.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < Math.Min(hex.Length, 8); i++)
            {
                if (hex[i].Length == 2 &&
                    byte.TryParse(hex[i], NumberStyles.HexNumber,
                        CultureInfo.InvariantCulture, out byte b))
                    data[i] = b;
            }
            return data;
        }

        private static void Report(IProgress<string>? progress, string msg)
            => progress?.Report(msg);
    }
}
