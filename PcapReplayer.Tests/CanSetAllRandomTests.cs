using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    [TestClass]
    public class CanSetAllRandomTests
    {
        private static DbcSignal CreateDbcSignal(string name)
        {
            return new DbcSignal
            {
                Name = name,
                StartBit = 0,
                Length = 8,
                IsLittleEndian = true,
                IsSigned = false,
                Factor = 1,
                Offset = 0,
                Min = 0,
                Max = 255,
                Unit = string.Empty
            };
        }

        private static SignalTxState CreateSignalState(string name)
        {
            return new SignalTxState
            {
                Signal = CreateDbcSignal(name),
                PhysicalValue = 127.0,
                RawValue = 127,
                IsMuted = true,
                GenMode = SignalGenMode.Fixed
            };
        }

        private static MessageTxState CreateMessage(string name, bool enabled = false, int periodMs = 100)
        {
            return new MessageTxState
            {
                Name = name,
                CanId = 0x123,
                IsExtended = false,
                Dlc = 8,
                Enabled = enabled,
                PeriodMs = periodMs
            };
        }

        [TestMethod]
        public void SetAllToRandom1s_StandardMessage_UpdatesCorrectly()
        {
            var msg = CreateMessage("TestMsg");
            var sig1 = CreateSignalState("Sig1");
            var sig2 = CreateSignalState("Sig2");
            msg.Signals.Add(sig1);
            msg.Signals.Add(sig2);

            var list = new List<MessageTxState> { msg };

            MainForm.SetAllToRandom1s(list);

            Assert.IsTrue(msg.Enabled, "Message must be enabled.");
            Assert.AreEqual(1000, msg.PeriodMs, "Message period must be 1s (1000ms).");

            Assert.IsFalse(sig1.IsMuted, "Signal 1 must be unmuted.");
            Assert.AreEqual(SignalGenMode.Random, sig1.GenMode, "Signal 1 gen mode must be Random.");

            Assert.IsFalse(sig2.IsMuted, "Signal 2 must be unmuted.");
            Assert.AreEqual(SignalGenMode.Random, sig2.GenMode, "Signal 2 gen mode must be Random.");
        }

        [TestMethod]
        public void SetAllToRandom1s_MultiplexedMessage_UpdatesAllGroupsCorrectly()
        {
            var msg = CreateMessage("MuxMsg");
            var normalSig = CreateSignalState("NormalSig");
            msg.Signals.Add(normalSig);

            // Setup multiplex structure
            var group1 = new MultiplexGroup
            {
                MuxValue = 1,
                Enabled = false,
                PeriodMs = 250
            };
            var groupSig1 = CreateSignalState("GroupSig1");
            group1.Signals.Add(groupSig1);

            var group2 = new MultiplexGroup
            {
                MuxValue = 2,
                Enabled = false,
                PeriodMs = 500
            };
            var groupSig2 = CreateSignalState("GroupSig2");
            group2.Signals.Add(groupSig2);

            msg.MultiplexGroups = new SortedDictionary<int, MultiplexGroup>
            {
                { 1, group1 },
                { 2, group2 }
            };

            var list = new List<MessageTxState> { msg };

            MainForm.SetAllToRandom1s(list);

            Assert.IsTrue(msg.Enabled, "Message must be enabled.");
            Assert.AreEqual(1000, msg.PeriodMs, "Message period must be 1s.");

            // Normal signal check
            Assert.IsFalse(normalSig.IsMuted, "Normal signal must be unmuted.");
            Assert.AreEqual(SignalGenMode.Random, normalSig.GenMode, "Normal signal gen mode must be Random.");

            // Group 1 checks
            Assert.IsTrue(group1.Enabled, "Group 1 must be enabled.");
            Assert.AreEqual(1000, group1.PeriodMs, "Group 1 rate must be 1s.");
            Assert.IsFalse(groupSig1.IsMuted, "Group 1 signal must be unmuted.");
            Assert.AreEqual(SignalGenMode.Random, groupSig1.GenMode, "Group 1 signal mode must be Random.");

            // Group 2 checks
            Assert.IsTrue(group2.Enabled, "Group 2 must be enabled.");
            Assert.AreEqual(1000, group2.PeriodMs, "Group 2 rate must be 1s.");
            Assert.IsFalse(groupSig2.IsMuted, "Group 2 signal must be unmuted.");
            Assert.AreEqual(SignalGenMode.Random, groupSig2.GenMode, "Group 2 signal mode must be Random.");
        }

        [TestMethod]
        public void SetAllToRandom1s_EmptyList_DoesNotThrow()
        {
            var list = new List<MessageTxState>();
            try
            {
                MainForm.SetAllToRandom1s(list);
            }
            catch (Exception ex)
            {
                Assert.Fail($"SetAllToRandom1s with empty list should not throw exceptions: {ex.Message}");
            }
        }
    }
}
