using System;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    [TestClass]
    public class CanLogConverterTests
    {
        private string _tempDir = string.Empty;

        [TestInitialize]
        public void Setup()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "CanLogConverterTests_" + Guid.NewGuid());
            Directory.CreateDirectory(_tempDir);
        }

        [TestCleanup]
        public void Teardown()
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, true);
        }

        [TestMethod]
        public void Convert_TrcFile_BuildsValidPcap()
        {
            // Arrange
            string trcPath = Path.Combine(_tempDir, "test.trc");
            File.WriteAllText(trcPath, @"
;$FILEVERSION=1.1
;$STARTTIME=46140.6177158796
;
;   Message Number
;   |         Time Offset (ms)
;   |         |        Type
;   |         |        |        ID (hex)
;   |         |        |        |     Data Length
;   |         |        |        |     |   Data Bytes (hex)
;   |         |        |        |     |   |
;---+--   ----+----  --+--  ----+---  +  -+ -- -- -- -- -- -- --
     1)        23.6  Rx     18F140CA  8  01 1E 00 28 00 00 00 00
     2)      5023.6  Rx     18F140CA  8  01 1E 00 28 00 00 00 00
     3)      5024.1  Rx     0CF00400  8  00 00 00 00 00 00 00 00
");

            string pcapPath = Path.Combine(_tempDir, "test.pcap");

            var opts = new ConversionOptions
            {
                InputFile        = trcPath,
                OutputPcap       = pcapPath,
                MetadataHeader   = "TEST|Unit|Mfg|DB|CAN1",
                BatchThresholdMs = 5.0,
                FramesPerPacket  = 10
            };

            // Act
            var result = CanLogConverter.Convert(opts);

            // Assert
            Assert.AreEqual(3, result.FramesParsed);
            Assert.AreEqual(2, result.PacketsWritten, "Should split into 2 packets due to the 5000ms gap between frame 1 and 2.");
            Assert.IsTrue(File.Exists(pcapPath));
            Assert.AreEqual(0, result.Warnings.Count);
        }

        [TestMethod]
        public void Convert_CandumpLog_BuildsValidPcap()
        {
            // Arrange
            string logPath = Path.Combine(_tempDir, "test.log");
            File.WriteAllText(logPath, @"
(1758823751.288213) can0 1CFE8801#FF7EFF7DFF7DFF7D R
(1758823751.288713) can0 18F9F400#625D674964535A60 R
(1758823751.289313) can0 1CFE8901#FF7DFF7DFF7DFF7D
(1758823760.000000) can0 1CFE8200#DE62FFFFDA62FFFF R
");

            string pcapPath = Path.Combine(_tempDir, "test.pcap");

            var opts = new ConversionOptions
            {
                InputFile        = logPath,
                OutputPcap       = pcapPath,
                MetadataHeader   = "TEST|Unit|Mfg|DB|CAN1",
                BatchThresholdMs = 5.0,
                FramesPerPacket  = 10
            };

            // Act
            var result = CanLogConverter.Convert(opts);

            // Assert
            Assert.AreEqual(4, result.FramesParsed);
            Assert.AreEqual(2, result.PacketsWritten, "Should split into 2 packets due to the ~9000ms gap between frame 3 and 4.");
            Assert.IsTrue(File.Exists(pcapPath));
            Assert.AreEqual(0, result.Warnings.Count);
        }

        [TestMethod]
        public void BuildUsrFrame_EncodesStandardAndExtendedCorrectly()
        {
            // Arrange standard ID
            var stdFrame = new CanFrame(0.0, 0x123, false, 8, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            byte[] stdUsr = CanLogConverter.BuildUsrFrame(stdFrame);
            Assert.AreEqual((byte)0x08, stdUsr[0], "Bit 7 should be 0 for standard ID");

            // Arrange extended ID
            var extFrame = new CanFrame(0.0, 0x18FECAFE, true, 8, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            byte[] extUsr = CanLogConverter.BuildUsrFrame(extFrame);
            Assert.AreEqual((byte)0x88, extUsr[0], "Bit 7 should be 1 for extended ID");
            Assert.AreEqual((byte)0x18, extUsr[1]);
            Assert.AreEqual((byte)0xFE, extUsr[2]);
            Assert.AreEqual((byte)0xCA, extUsr[3]);
            Assert.AreEqual((byte)0xFE, extUsr[4]);
        }
    }
}
