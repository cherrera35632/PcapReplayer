using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    /// <summary>
    /// Tests for the CAN-Generator live-search feature.
    /// All tests call the two internal static helpers extracted from MainForm
    /// (<see cref="MainForm.NormalizeSearchQuery"/> and
    ///  <see cref="MainForm.MessageMatchesSearchQuery"/>) so no WinForms controls
    /// are needed.
    /// </summary>
    [TestClass]
    public class CanSearchTests
    {
        // ── helpers ──────────────────────────────────────────────────────────────────────

        private static MessageTxState Msg(string name, uint canId, bool isExtended = true)
            => new MessageTxState { Name = name, CanId = canId, IsExtended = isExtended, Dlc = 8 };

        // ═══════════════════════════════════════════════════════════════════════════════
        // NormalizeSearchQuery
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void Normalize_NoPrefixPassthrough()
        {
            Assert.AreEqual("18FD9BFE", MainForm.NormalizeSearchQuery("18FD9BFE"));
        }

        [TestMethod]
        public void Normalize_LowerCasePrefix_Stripped()
        {
            Assert.AreEqual("18fd9bfe", MainForm.NormalizeSearchQuery("0x18fd9bfe"));
        }

        [TestMethod]
        public void Normalize_UpperCasePrefix_Stripped()
        {
            Assert.AreEqual("18FD9BFE", MainForm.NormalizeSearchQuery("0X18FD9BFE"));
        }

        [TestMethod]
        public void Normalize_MixedCase0x_Stripped()
        {
            Assert.AreEqual("18FD", MainForm.NormalizeSearchQuery("0x18FD"));
        }

        [TestMethod]
        public void Normalize_PlainName_Unchanged()
        {
            Assert.AreEqual("ENG_SPEED", MainForm.NormalizeSearchQuery("ENG_SPEED"));
        }

        [TestMethod]
        public void Normalize_EmptyString_ReturnsEmpty()
        {
            Assert.AreEqual(string.Empty, MainForm.NormalizeSearchQuery(string.Empty));
        }

        [TestMethod]
        public void Normalize_JustPrefix_ReturnsEmpty()
        {
            // "0x" with nothing after → strips to empty string
            Assert.AreEqual(string.Empty, MainForm.NormalizeSearchQuery("0x"));
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // MessageMatchesSearchQuery — name matching
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void Match_ExactName_CaseSensitive_Matches()
        {
            var msg = Msg("ENG_SPEED", 0x18FD9BFE);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "ENG_SPEED"));
        }

        [TestMethod]
        public void Match_NameSubstring_Matches()
        {
            var msg = Msg("ENG_SPEED", 0x18FD9BFE);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "ENG"));
        }

        [TestMethod]
        public void Match_NameSubstring_CaseInsensitive_Matches()
        {
            var msg = Msg("ENG_SPEED", 0x18FD9BFE);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "eng_sp"));
        }

        [TestMethod]
        public void Match_MiddleOfName_Matches()
        {
            var msg = Msg("TRANS_TEMP_SENSOR", 0x18FC00FE);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "TEMP"));
        }

        [TestMethod]
        public void Match_NameNotPresent_NoMatch()
        {
            var msg = Msg("ENG_SPEED", 0x18FD9BFE);
            Assert.IsFalse(MainForm.MessageMatchesSearchQuery(msg, "TRANS"));
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // MessageMatchesSearchQuery — CAN-ID matching (extended 29-bit)
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void Match_FullHexId_Extended_Matches()
        {
            var msg = Msg("MSG_A", 0x18FD9BFE, isExtended: true);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "18FD9BFE"));
        }

        [TestMethod]
        public void Match_PartialHexPrefix_Extended_Matches()
        {
            var msg = Msg("MSG_A", 0x18FD9BFE, isExtended: true);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "18FD"));
        }

        [TestMethod]
        public void Match_HexId_CaseInsensitive_Matches()
        {
            var msg = Msg("MSG_A", 0x18FD9BFE, isExtended: true);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "18fd9bfe"));
        }

        [TestMethod]
        public void Match_HexId_MixedCase_Matches()
        {
            var msg = Msg("MSG_A", 0x18FD9BFE, isExtended: true);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "18Fd9B"));
        }

        [TestMethod]
        public void Match_HexIdSuffix_DoesNotMatch()
        {
            // ID matching is prefix-only; a suffix alone must not match
            var msg = Msg("MSG_A", 0x18FD9BFE, isExtended: true);
            Assert.IsFalse(MainForm.MessageMatchesSearchQuery(msg, "9BFE"));
        }

        [TestMethod]
        public void Match_WrongHexPrefix_DoesNotMatch()
        {
            var msg = Msg("MSG_A", 0x18FD9BFE, isExtended: true);
            Assert.IsFalse(MainForm.MessageMatchesSearchQuery(msg, "1CFC"));
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // MessageMatchesSearchQuery — standard 11-bit CAN ID (3-digit hex)
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void Match_StandardId_FullHex_Matches()
        {
            var msg = Msg("STD_MSG", 0x123, isExtended: false);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "123"));
        }

        [TestMethod]
        public void Match_StandardId_Prefix_Matches()
        {
            var msg = Msg("STD_MSG", 0x123, isExtended: false);
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, "12"));
        }

        [TestMethod]
        public void Match_StandardId_ExtendedFormatDoesNotMatch()
        {
            // Standard frame is formatted as 3-digit hex, so 8-char query won't match
            var msg = Msg("STD_MSG", 0x123, isExtended: false);
            Assert.IsFalse(MainForm.MessageMatchesSearchQuery(msg, "00000123"));
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // MessageMatchesSearchQuery — empty / edge cases
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void Match_EmptyQuery_ReturnsFalse()
        {
            var msg = Msg("ENG_SPEED", 0x18FD9BFE);
            Assert.IsFalse(MainForm.MessageMatchesSearchQuery(msg, string.Empty));
        }

        [TestMethod]
        public void Match_QueryLongerThanId_DoesNotMatch()
        {
            // 9-character query against an 8-character hex ID must never match
            var msg = Msg("MSG_A", 0x18FD9BFE, isExtended: true);
            Assert.IsFalse(MainForm.MessageMatchesSearchQuery(msg, "18FD9BFEFF"));
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // Round-trip: NormalizeSearchQuery → MessageMatchesSearchQuery
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void RoundTrip_0xPrefixedHex_MatchesAfterNormalize()
        {
            var msg   = Msg("MSG_A", 0x18FD9BFE, isExtended: true);
            string q  = MainForm.NormalizeSearchQuery("0x18FD9BFE");
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, q),
                "0x-prefixed input should match after normalization.");
        }

        [TestMethod]
        public void RoundTrip_0xPrefixedPartialHex_MatchesAfterNormalize()
        {
            var msg  = Msg("MSG_A", 0x18FD9BFE, isExtended: true);
            string q = MainForm.NormalizeSearchQuery("0x18FD");
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, q));
        }

        [TestMethod]
        public void RoundTrip_NameWithoutPrefix_MatchesAfterNormalize()
        {
            var msg  = Msg("ENG_SPEED", 0x18FD9BFE);
            string q = MainForm.NormalizeSearchQuery("eng");
            Assert.IsTrue(MainForm.MessageMatchesSearchQuery(msg, q));
        }
    }
}
