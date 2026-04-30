using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PcapReplayer
{
    public enum DetectedProtocol { Unknown, USR, PEAK, Mixed }

    public record PcapAnalysisResult(
        DetectedProtocol Protocol,
        int TotalUdpPacketsScanned,
        int UsrPacketsFound,
        int PeakPacketsFound,
        List<string> SourceEndpoints,
        string? DetectedUsrMetadataString);

    /// <summary>
    /// Scans the first <see cref="MAX_PACKETS_TO_SCAN"/> UDP payloads in a PCAP file and
    /// identifies whether the traffic is USR-CANET200 format, PEAK CAN Gateway format, or mixed.
    /// Packet classification is delegated to <see cref="UsrPacketHelper"/> so the logic
    /// is independently unit-testable.
    /// </summary>
    public static class PcapAnalyzer
    {
        public const int MAX_PACKETS_TO_SCAN = 300;

        public static Task<PcapAnalysisResult> AnalyseAsync(string pcapFile)
            => Task.Run(() => Analyse(pcapFile));

        private static PcapAnalysisResult Analyse(string pcapFile)
        {
            int usrCount = 0, peakCount = 0, udpScanned = 0;
            string? detectedUsrString = null;
            var endpoints = new HashSet<string>(StringComparer.Ordinal);

            try
            {
                using var fs = new FileStream(pcapFile, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var br = new BinaryReader(fs);

                // ── Global PCAP header (24 bytes) ────────────────────────────
                if (fs.Length < 24) return Empty();

                br.ReadUInt32(); // magic
                br.ReadUInt16(); // versionMajor
                br.ReadUInt16(); // versionMinor
                br.ReadInt32();  // thiszone
                br.ReadUInt32(); // sigfigs
                br.ReadUInt32(); // snaplen
                uint network = br.ReadUInt32();

                // ── Packet loop ───────────────────────────────────────────────
                while (fs.Position < fs.Length && udpScanned < MAX_PACKETS_TO_SCAN)
                {
                    if (fs.Length - fs.Position < 16) break;

                    br.ReadUInt32(); // tsSec
                    br.ReadUInt32(); // tsUsec
                    uint inclLen = br.ReadUInt32();
                    br.ReadUInt32(); // origLen

                    if (fs.Length - fs.Position < inclLen) break;
                    byte[] pkt = br.ReadBytes((int)inclLen);

                    int ipOffset = GetIpOffset(network, pkt, (int)inclLen);
                    if (ipOffset < 0 || ipOffset >= inclLen) continue;
                    if (pkt[ipOffset] != 0x45) continue;       // Not IPv4
                    if (pkt[ipOffset + 9] != 17) continue;     // Not UDP

                    int ihl = (pkt[ipOffset] & 0x0F) * 4;
                    int udpOffset = ipOffset + ihl;
                    if (udpOffset + 8 >= inclLen) continue;

                    // Source IP:port for endpoint tracking
                    string srcIp = $"{pkt[ipOffset+12]}.{pkt[ipOffset+13]}.{pkt[ipOffset+14]}.{pkt[ipOffset+15]}";
                    ushort srcPort = (ushort)((pkt[udpOffset] << 8) | pkt[udpOffset + 1]);
                    endpoints.Add($"{srcIp}:{srcPort}");

                    int payloadOffset = udpOffset + 8;
                    int payloadLen    = (int)inclLen - payloadOffset;
                    if (payloadLen <= 0) continue;

                    byte[] payload = new byte[payloadLen];
                    Array.Copy(pkt, payloadOffset, payload, 0, payloadLen);
                    udpScanned++;

                    // ── Classify via shared helper ────────────────────────────
                    if (UsrPacketHelper.IsPeakFrame(payload))
                    {
                        peakCount++;
                    }
                    else if (UsrPacketHelper.IsUsrPacket(payload, out string? metaString))
                    {
                        usrCount++;
                        detectedUsrString ??= metaString;
                    }
                }
            }
            catch
            {
                // Corrupt / unsupported file — return whatever we accumulated
            }

            var protocol = (usrCount > 0, peakCount > 0) switch
            {
                (true,  false) => DetectedProtocol.USR,
                (false, true)  => DetectedProtocol.PEAK,
                (true,  true)  => DetectedProtocol.Mixed,
                _              => DetectedProtocol.Unknown
            };

            return new PcapAnalysisResult(
                protocol, udpScanned, usrCount, peakCount,
                new List<string>(endpoints), detectedUsrString);

            PcapAnalysisResult Empty() =>
                new(DetectedProtocol.Unknown, 0, 0, 0, new List<string>(), null);
        }

        private static int GetIpOffset(uint network, byte[] pkt, int inclLen)
        {
            if (network == 1)   // Ethernet
            {
                if (inclLen < 14) return -1;
                int off = 14;
                if (pkt[12] == 0x81 && pkt[13] == 0x00) off = 18; // VLAN
                return off;
            }
            if (network == 276) // Linux SLL2
            {
                if (inclLen < 20) return -1;
                return 20;
            }
            if (inclLen > 0 && pkt[0] == 0x45) return 0; // Raw IP
            return -1;
        }
    }
}
