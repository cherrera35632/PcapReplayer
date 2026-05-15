using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    [TestClass]
    public class DbcParserTests
    {
        private const uint Eec1RawId = 0x8CF00400;
        private const uint Et1RawId  = 0x98FEEE00;

        private static string SyntheticDbc => $@"
BO_ {Eec1RawId} EEC1: 8 Vector__XXX
 SG_ EngineSpeed : 24|16@1+ (0.125,0) [0|8031.875] ""rpm"" Vector__XXX
 SG_ DriverMode : 8|4@1+ (1,0) [0|15] """" Vector__XXX
 SG_ MuxSwitch M : 0|4@1+ (1,0) [0|15] """" Vector__XXX
 SG_ SkipMux m0 : 12|4@1+ (1,0) [0|15] """" Vector__XXX
BO_ {Et1RawId} ET1: 8 Vector__XXX
 SG_ OilTemp : 0|8@1- (1,-40) [-40|210] ""degC"" Vector__XXX
BO_ 291 StdMsg: 8 Vector__XXX
 SG_ Flag : 0|1@1+ (1,0) [0|1] """" Vector__XXX
VAL_ {Eec1RawId} DriverMode 0 ""Off"" 1 ""On"";
CM_ SG_ {Eec1RawId} EngineSpeed ""SPN 190"";
";

        [TestMethod]
        public void Parse_SyntheticDbc_LoadsThreeMessagesAndSixSignals()
        {
            var db = DbcParser.Parse(SyntheticDbc);

            Assert.AreEqual(3, db.MessageCount);
            Assert.AreEqual(6, db.SignalCount);
            CollectionAssert.AreEquivalent(new[] { "EEC1", "ET1", "StdMsg" }, db.Messages.Select(m => m.Name).ToArray());
        }

        [TestMethod]
        public void Parse_ExtendedFlag_IsStrippedFromCanId()
        {
            var db = DbcParser.Parse(SyntheticDbc);
            var eec1 = db.Messages.Single(m => m.Name == "EEC1");

            Assert.IsTrue(eec1.IsExtended);
            Assert.AreEqual(0x0CF00400u, eec1.CanId);
        }

        [TestMethod]
        public void Parse_SignalScalingAndUnits_AreExtracted()
        {
            var db = DbcParser.Parse(SyntheticDbc);
            var signal = db.Messages.Single(m => m.Name == "EEC1").Signals.Single(s => s.Name == "EngineSpeed");

            Assert.AreEqual(24, signal.StartBit);
            Assert.AreEqual(16, signal.Length);
            Assert.IsTrue(signal.IsLittleEndian);
            Assert.IsFalse(signal.IsSigned);
            Assert.AreEqual(0.125, signal.Factor, 1e-9);
            Assert.AreEqual(0.0, signal.Offset, 1e-9);
            Assert.AreEqual(0.0, signal.Min, 1e-9);
            Assert.AreEqual(8031.875, signal.Max, 1e-9);
            Assert.AreEqual("rpm", signal.Unit);
            Assert.AreEqual(190, signal.Spn);
        }

        [TestMethod]
        public void Parse_ValueTable_AttachesToCorrectSignal()
        {
            var db = DbcParser.Parse(SyntheticDbc);
            var signal = db.Messages.Single(m => m.Name == "EEC1").Signals.Single(s => s.Name == "DriverMode");

            Assert.IsNotNull(signal.ValueTable);
            Assert.AreEqual("Off", signal.ValueTable![0]);
            Assert.AreEqual("On", signal.ValueTable[1]);
        }

        [TestMethod]
        public void Parse_MultiplexedSignal_IsParsedWithIndicator()
        {
            var db = DbcParser.Parse(SyntheticDbc);
            var eec1 = db.Messages.Single(m => m.Name == "EEC1");

            var muxSig = eec1.Signals.SingleOrDefault(s => s.Name == "SkipMux");
            Assert.IsNotNull(muxSig);
            Assert.AreEqual("m0", muxSig!.MultiplexIndicator);

            var muxor = eec1.Signals.SingleOrDefault(s => s.Name == "MuxSwitch");
            Assert.IsNotNull(muxor);
            Assert.AreEqual("M", muxor!.MultiplexIndicator);

            // Normal signals have null indicator
            var normal = eec1.Signals.Single(s => s.Name == "EngineSpeed");
            Assert.IsNull(normal.MultiplexIndicator);
        }

        [TestMethod]
        public void Parse_StandardCanMessage_IsNotClassifiedAsJ1939()
        {
            var db = DbcParser.Parse(SyntheticDbc);
            var std = db.Messages.Single(m => m.Name == "StdMsg");

            Assert.IsFalse(J1939IdDecoder.TryDecode(std.CanId, std.IsExtended, out _));
        }
    }
}
