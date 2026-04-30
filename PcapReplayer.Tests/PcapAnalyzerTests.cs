using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PcapReplayer;

namespace PcapReplayer.Tests
{
    /// <summary>
    /// Integration tests for <see cref="PcapAnalyzer"/> using synthetic in-memory PCAP files.
    ///
    /// Each test builds a minimal but structurally correct PCAP binary, writes it to a
    /// temp file, runs <see cref="PcapAnalyzer.AnalyseAsync"/>, and asserts on the result.
    /// Temp files are cleaned up in <see cref="Cleanup"/>.
    /// </summary>
    [TestClass]
    public class PcapAnalyzerTests
    {
        private readonly List<string> _tempFiles = new();

        [TestCleanup]
        public void Cleanup()
        {
            foreach (var f in _tempFiles)
                try { File.Delete(f); } catch { }
        }

        // ── PCAP builder helpers ──────────────────────────────────────────────

        /// <summary>
        /// Builds a minimal PCAP byte array (link-layer type = 1, Ethernet) containing
        /// UDP packets with the given payloads. All packets share the same source IP 10.0.0.1
        /// unless overridden.
        /// </summary>
        private static byte[] BuildPcap(
            IEnumerable<byte[]> payloads,
            string srcIp = "10.0.0.1",
            ushort srcPort = 35217,
            ushort dstPort = 35217)
        {
            using var ms  = new MemoryStream();
            using var bw  = new BinaryWriter(ms);

            // ── Global header ─────────────────────────────────────────────────
            bw.Write(0xA1B2C3D4u); // magic (little-endian byte order on Windows)
            bw.Write((ushort)2);   // version major
            bw.Write((ushort)4);   // version minor
            bw.Write(0);           // thiszone
            bw.Write(0u);          // sigfigs
            bw.Write(65535u);      // snaplen
            bw.Write(1u);          // network: Ethernet

            byte[] srcIpBytes = srcIp.Split('.').Select(byte.Parse).ToArray();

            foreach (byte[] payload in payloads)
            {
                int ipTotalLen  = 20 + 8 + payload.Length;
                int udpLen      = 8  + payload.Length;
                int etherLen    = 14 + ipTotalLen;

                // Packet record header
                bw.Write(0u);              // ts_sec
                bw.Write(0u);             // ts_usec
                bw.Write((uint)etherLen); // incl_len
                bw.Write((uint)etherLen); // orig_len

                // Ethernet header (14 bytes)
                bw.Write(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }); // dst MAC
                bw.Write(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }); // src MAC
                bw.Write((byte)0x08); bw.Write((byte)0x00);                   // EtherType IPv4

                // IP header (20 bytes) — big-endian fields written manually
                bw.Write((byte)0x45);                               // version+IHL
                bw.Write((byte)0x00);                               // DSCP/ECN
                bw.Write((byte)(ipTotalLen >> 8));                  // total len hi
                bw.Write((byte)(ipTotalLen & 0xFF));                // total len lo
                bw.Write(new byte[] { 0x00, 0x00, 0x00, 0x00 });   // id, flags
                bw.Write((byte)0x40);                               // TTL
                bw.Write((byte)0x11);                               // Protocol: UDP
                bw.Write(new byte[] { 0x00, 0x00 });                // checksum (skip)
                bw.Write(srcIpBytes);                               // src IP
                bw.Write(new byte[] { 127, 0, 0, 1 });             // dst IP 127.0.0.1

                // UDP header (8 bytes)
                bw.Write((byte)(srcPort >> 8)); bw.Write((byte)(srcPort & 0xFF));
                bw.Write((byte)(dstPort >> 8)); bw.Write((byte)(dstPort & 0xFF));
                bw.Write((byte)(udpLen   >> 8)); bw.Write((byte)(udpLen   & 0xFF));
                bw.Write(new byte[] { 0x00, 0x00 }); // checksum

                // Payload
                bw.Write(payload);
            }

            return ms.ToArray();
        }

        /// <summary>Writes PCAP bytes to a temp file and returns the path.</summary>
        private string WriteTempPcap(byte[] pcapData)
        {
            string path = Path.GetTempFileName();
            File.WriteAllBytes(path, pcapData);
            _tempFiles.Add(path);
            return path;
        }

        // ── Helpers matching gateway parser test fixtures ─────────────────────

        private static byte[] UsrMeta(string meta) => Encoding.ASCII.GetBytes(meta);

        private static byte[] PeakFrame(byte msgTypeLowByte = 0x80, byte dlc = 8)
        {
            // Correct PEAK CAN Gateway wire format (mirrors Classes.cs ParseCANMessagesFromPEAKUDPFrames)
            // [0..1] Frame length (big-endian), [2..3] Message type (big-endian 0x0080 for CAN 2.0)
            // [21] DLC, [24..27] CAN ID, [28+] data
            int frameLen = 28 + dlc;
            var frame    = new byte[frameLen];
            frame[0]  = (byte)(frameLen >> 8);
            frame[1]  = (byte)(frameLen & 0xFF);
            frame[2]  = 0x00;             // high byte of type (always 0x00)
            frame[3]  = msgTypeLowByte;   // low byte: 0x80=CAN2.0, 0x81=CAN2.0+CRC, 0x90=FD
            frame[21] = dlc;
            frame[24] = 0x18; frame[25] = 0xFE; frame[26] = 0xF1; frame[27] = 0x18; // J1939 CAN ID
            for (int i = 0; i < dlc; i++) frame[28 + i] = (byte)(i + 1);
            return frame;
        }

        private static byte[] UsrMixedPacket()
        {
            byte[] header = Encoding.ASCII.GetBytes("ASSET|P|R|J0|C1");
            byte[] frame  = new byte[13];
            frame[0] = 0x88;  // info byte — non-ASCII
            frame[1] = 0x18; frame[2] = 0xFE; frame[3] = 0xF1; frame[4] = 0x00; // CAN ID
            return Concat(header, frame);
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  PcapAnalyzer Tests
        // ══════════════════════════════════════════════════════════════════════

        // T-PA-20
        [TestMethod]
        public async Task Analyse_NonExistentFile_ReturnsUnknown()
        {
            var result = await PcapAnalyzer.AnalyseAsync(@"C:\this\does\not\exist.pcap");
            Assert.AreEqual(DetectedProtocol.Unknown, result.Protocol);
            Assert.AreEqual(0, result.TotalUdpPacketsScanned);
        }

        // T-PA-21
        [TestMethod]
        public async Task Analyse_PeakOnlyPayloads_ReturnsPeak()
        {
            var payloads = Enumerable.Repeat(PeakFrame(), 5).ToList();
            string path  = WriteTempPcap(BuildPcap(payloads));

            var result = await PcapAnalyzer.AnalyseAsync(path);

            Assert.AreEqual(DetectedProtocol.PEAK, result.Protocol);
            Assert.AreEqual(5, result.PeakPacketsFound);
            Assert.AreEqual(0, result.UsrPacketsFound);
        }

        // T-PA-22
        [TestMethod]
        public async Task Analyse_UsrPureMetadataPayloads_ReturnsUsr()
        {
            var payloads = Enumerable.Repeat(UsrMeta("WELL-001|P|R|J0|C1"), 5).ToList();
            string path  = WriteTempPcap(BuildPcap(payloads));

            var result = await PcapAnalyzer.AnalyseAsync(path);

            Assert.AreEqual(DetectedProtocol.USR, result.Protocol);
            Assert.IsTrue(result.UsrPacketsFound > 0);
            Assert.AreEqual(0, result.PeakPacketsFound);
        }

        // T-PA-23
        [TestMethod]
        public async Task Analyse_UsrMixedPayloads_ReturnsUsr()
        {
            var payloads = Enumerable.Repeat(UsrMixedPacket(), 3).ToList();
            string path  = WriteTempPcap(BuildPcap(payloads));

            var result = await PcapAnalyzer.AnalyseAsync(path);

            Assert.AreEqual(DetectedProtocol.USR, result.Protocol);
            Assert.IsTrue(result.UsrPacketsFound > 0);
        }

        // T-PA-24
        [TestMethod]
        public async Task Analyse_BothProtocolsPresent_ReturnsMixed()
        {
            var payloads = new List<byte[]>();
            payloads.AddRange(Enumerable.Repeat(UsrMeta("PUMP|P|R|J0|C1"), 3));
            payloads.AddRange(Enumerable.Repeat(PeakFrame(), 3));

            string path = WriteTempPcap(BuildPcap(payloads));

            var result = await PcapAnalyzer.AnalyseAsync(path);

            Assert.AreEqual(DetectedProtocol.Mixed, result.Protocol);
            Assert.IsTrue(result.UsrPacketsFound  > 0);
            Assert.IsTrue(result.PeakPacketsFound > 0);
        }

        // T-PA-25
        [TestMethod]
        public async Task Analyse_UsrWithMetadataString_ExtractsFirstString()
        {
            const string expected = "WELL-001|P|R|J0|C1|3";
            var payloads = new List<byte[]>
            {
                UsrMeta(expected),
                UsrMeta("OTHER-001|P|R|J0|C2|3")  // second packet — should NOT be returned
            };
            string path = WriteTempPcap(BuildPcap(payloads));

            var result = await PcapAnalyzer.AnalyseAsync(path);

            Assert.AreEqual(DetectedProtocol.USR, result.Protocol);
            Assert.AreEqual(expected, result.DetectedUsrMetadataString,
                "Must extract the FIRST metadata string encountered, not later ones.");
        }

        // T-PA-26
        [TestMethod]
        public async Task Analyse_DetectsSourceEndpoints()
        {
            var payloads = new[] { UsrMeta("SITE|P|R|J0|C1") };
            string path  = WriteTempPcap(BuildPcap(payloads, srcIp: "10.10.1.50", srcPort: 35281));

            var result = await PcapAnalyzer.AnalyseAsync(path);

            Assert.IsTrue(result.SourceEndpoints.Contains("10.10.1.50:35281"),
                $"Expected 10.10.1.50:35281 in: [{string.Join(", ", result.SourceEndpoints)}]");
        }

        // T-PA-27
        [TestMethod]
        public async Task Analyse_NoParsableUdpPackets_ReturnsUnknown()
        {
            // PCAP file with global header only — no packets
            byte[] empty = BuildPcap(Enumerable.Empty<byte[]>());
            string path  = WriteTempPcap(empty);

            var result = await PcapAnalyzer.AnalyseAsync(path);

            Assert.AreEqual(DetectedProtocol.Unknown, result.Protocol);
            Assert.AreEqual(0, result.TotalUdpPacketsScanned);
        }

        // T-PA-28: Scan cap — MAX_PACKETS_TO_SCAN is honoured
        [TestMethod]
        public async Task Analyse_HonoursScanCap_StopsAt300()
        {
            // Create 310 USR packets — analyser should stop at 300
            var payloads = Enumerable.Repeat(UsrMeta("SITE|P|R|J0|C1"), 310).ToList();
            string path  = WriteTempPcap(BuildPcap(payloads));

            var result = await PcapAnalyzer.AnalyseAsync(path);

            Assert.AreEqual(PcapAnalyzer.MAX_PACKETS_TO_SCAN, result.TotalUdpPacketsScanned,
                $"Analyser must stop at exactly {PcapAnalyzer.MAX_PACKETS_TO_SCAN} packets.");
        }

        // T-PA-29: PEAK detection not fooled by USR metadata containing pipe characters
        [TestMethod]
        public async Task Analyse_UsrPayload_NotMisclassifiedAsPeak()
        {
            // A USR metadata payload is all ASCII — IsPeakFrame must return false for it
            var payloads = new[] { UsrMeta("WELL-001|P|R|J0|C1") };
            string path  = WriteTempPcap(BuildPcap(payloads));

            var result = await PcapAnalyzer.AnalyseAsync(path);

            Assert.AreEqual(0, result.PeakPacketsFound,
                "USR metadata packet must not be counted as a PEAK frame.");
            Assert.AreEqual(DetectedProtocol.USR, result.Protocol);
        }

        // T-PA-30: PEAK detection not fooled by binary-only USR CAN frames
        [TestMethod]
        public async Task Analyse_PureBinaryUsrCANFrames_ClassifiedAsUnknown()
        {
            // Binary USR CAN frames without a metadata header — not identifiable as USR
            // and not identifiable as PEAK; should contribute to Unknown
            byte[] frame = new byte[13];
            frame[0] = 0x88;  // non-ASCII info byte
            frame[1] = 0x18; frame[2] = 0xFE; frame[3] = 0xF1; frame[4] = 0x00;

            var payloads = Enumerable.Repeat(frame, 10).ToList();
            string path  = WriteTempPcap(BuildPcap(payloads));

            var result = await PcapAnalyzer.AnalyseAsync(path);

            // Pure binary CAN frames have no detectable USR header, and don't match PEAK signature
            Assert.AreEqual(0, result.UsrPacketsFound);
            Assert.AreEqual(0, result.PeakPacketsFound);
            Assert.AreEqual(DetectedProtocol.Unknown, result.Protocol);
        }
    }
}
