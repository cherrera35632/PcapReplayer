using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    [TestClass]
    public class SignalEncoderTests
    {
        [TestMethod]
        public void TryEncodePhysical_EngineSpeed_ReturnsExpectedRaw()
        {
            var signal = CreateSignal(startBit: 24, length: 16, littleEndian: true, signed: false, factor: 0.125, offset: 0, min: 0, max: 8031.875);

            bool ok = SignalEncoder.TryEncodePhysical(signal, 1234.5, out long raw, out string? error);

            Assert.IsTrue(ok, error);
            Assert.AreEqual(9876, raw);
        }

        [TestMethod]
        public void TryEncodePhysical_SignedBoundaryAtPositiveMax_Succeeds()
        {
            var signal = CreateSignal(0, 8, true, true, 1, 0, -128, 127);

            bool ok = SignalEncoder.TryEncodePhysical(signal, 127, out long raw, out string? error);

            Assert.IsTrue(ok, error);
            Assert.AreEqual(127, raw);
        }

        [TestMethod]
        public void TryEncodePhysical_SignedBoundaryAtNegativeMin_Succeeds()
        {
            var signal = CreateSignal(0, 8, true, true, 1, 0, -128, 127);

            bool ok = SignalEncoder.TryEncodePhysical(signal, -128, out long raw, out string? error);

            Assert.IsTrue(ok, error);
            Assert.AreEqual(-128, raw);
        }

        [TestMethod]
        public void TryEncodePhysical_OutOfRangePhysical_FailsWithError()
        {
            var signal = CreateSignal(0, 8, true, false, 1, 0, 0, 100);

            bool ok = SignalEncoder.TryEncodePhysical(signal, 101, out _, out string? error);

            Assert.IsFalse(ok);
            Assert.IsFalse(string.IsNullOrWhiteSpace(error));
        }

        [TestMethod]
        public void TryEncodePhysical_RoundedRawOutsideBitWidth_Fails()
        {
            var signal = CreateSignal(0, 4, true, false, 1, 0, 0, 15.6);

            bool ok = SignalEncoder.TryEncodePhysical(signal, 15.6, out _, out string? error);

            Assert.IsFalse(ok);
            StringAssert.Contains(error!, "does not fit");
        }

        [TestMethod]
        public void PackBits_Intel16Bit_StartBit0_PacksLittleEndianBytes()
        {
            var signal = CreateSignal(0, 16, true, false, 1, 0, 0, 65535);
            var data = new byte[8];

            SignalEncoder.PackBits(data, signal, 0x1234);

            Assert.AreEqual(0x34, data[0]);
            Assert.AreEqual(0x12, data[1]);
        }

        [TestMethod]
        public void PackBits_Motorola16Bit_StartBit7_PacksBigEndianBytes()
        {
            var signal = CreateSignal(7, 16, false, false, 1, 0, 0, 65535);
            var data = new byte[8];

            SignalEncoder.PackBits(data, signal, 0x1234);

            Assert.AreEqual(0x12, data[0]);
            Assert.AreEqual(0x34, data[1]);
        }

        [TestMethod]
        public void PackBits_Intel4Bit_MidByte_PacksExpectedNibble()
        {
            var signal = CreateSignal(4, 4, true, false, 1, 0, 0, 15);
            var data = new byte[8];

            SignalEncoder.PackBits(data, signal, 0xA);

            Assert.AreEqual(0xA0, data[0]);
        }

        [TestMethod]
        public void PackBits_Motorola4Bit_MidByte_PacksExpectedNibble()
        {
            var signal = CreateSignal(3, 4, false, false, 1, 0, 0, 15);
            var data = new byte[8];

            SignalEncoder.PackBits(data, signal, 0xA);

            Assert.AreEqual(0x0A, data[0]);
        }

        [TestMethod]
        public void PackBits_Intel18Bit_SpansThreeBytes()
        {
            var signal = CreateSignal(0, 18, true, false, 1, 0, 0, 262143);
            var data = new byte[8];

            SignalEncoder.PackBits(data, signal, 0x2AAAA);

            Assert.AreEqual(0xAA, data[0]);
            Assert.AreEqual(0xAA, data[1]);
            Assert.AreEqual(0x02, data[2]);
        }

        private static DbcSignal CreateSignal(int startBit, int length, bool littleEndian, bool signed, double factor, double offset, double min, double max)
            => new()
            {
                Name           = "Sig",
                StartBit       = startBit,
                Length         = length,
                IsLittleEndian = littleEndian,
                IsSigned       = signed,
                Factor         = factor,
                Offset         = offset,
                Min            = min,
                Max            = max,
                Unit           = string.Empty
            };
    }
}
