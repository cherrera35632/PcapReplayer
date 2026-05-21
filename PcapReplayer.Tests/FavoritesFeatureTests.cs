using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    /// <summary>
    /// Tests for the "Mark Favorite" feature introduced in MessageTxState.
    /// All tests are pure model-layer — no WinForms controls are created.
    /// </summary>
    [TestClass]
    public class FavoritesFeatureTests
    {
        // ── helpers ──────────────────────────────────────────────────────────────────────

        private static MessageTxState MakeMessage(string name, uint canId = 0x18FD9BFE,
            bool isExtended = true, bool enabled = true)
            => new MessageTxState
            {
                Name       = name,
                CanId      = canId,
                IsExtended = isExtended,
                Dlc        = 8,
                Enabled    = enabled
            };

        // ── IsFavorite default ────────────────────────────────────────────────────────────

        [TestMethod]
        public void IsFavorite_DefaultsToFalse()
        {
            var msg = MakeMessage("ENG_SPEED");
            Assert.IsFalse(msg.IsFavorite, "A newly created MessageTxState must not be favorited by default.");
        }

        // ── Toggle ────────────────────────────────────────────────────────────────────────

        [TestMethod]
        public void IsFavorite_CanBeSetToTrue()
        {
            var msg = MakeMessage("ENG_SPEED");
            msg.IsFavorite = true;
            Assert.IsTrue(msg.IsFavorite);
        }

        [TestMethod]
        public void IsFavorite_CanBeToggledOffAfterBeingSet()
        {
            var msg = MakeMessage("ENG_SPEED");
            msg.IsFavorite = true;
            msg.IsFavorite = false;
            Assert.IsFalse(msg.IsFavorite, "IsFavorite must be clearable after being set.");
        }

        [TestMethod]
        public void IsFavorite_SettingTrueTwiceRemainsTrue()
        {
            var msg = MakeMessage("ENG_SPEED");
            msg.IsFavorite = true;
            msg.IsFavorite = true;   // idempotent
            Assert.IsTrue(msg.IsFavorite);
        }

        // ── Multi-message independence ────────────────────────────────────────────────────

        [TestMethod]
        public void IsFavorite_IsIndependentPerMessage()
        {
            var msgA = MakeMessage("ENG_SPEED");
            var msgB = MakeMessage("TRANS_TEMP");
            var msgC = MakeMessage("FUEL_RATE");

            msgA.IsFavorite = true;

            Assert.IsTrue(msgA.IsFavorite,  "msgA should be favorited.");
            Assert.IsFalse(msgB.IsFavorite, "msgB should be unaffected.");
            Assert.IsFalse(msgC.IsFavorite, "msgC should be unaffected.");
        }

        [TestMethod]
        public void IsFavorite_MultipleMessagesCanBeFavoritedSimultaneously()
        {
            var msgs = new[]
            {
                MakeMessage("A"), MakeMessage("B"), MakeMessage("C"), MakeMessage("D")
            };

            msgs[0].IsFavorite = true;
            msgs[2].IsFavorite = true;

            Assert.IsTrue(msgs[0].IsFavorite);
            Assert.IsFalse(msgs[1].IsFavorite);
            Assert.IsTrue(msgs[2].IsFavorite);
            Assert.IsFalse(msgs[3].IsFavorite);
        }

        // ── Favorites bar population logic ────────────────────────────────────────────────

        /// <summary>
        /// Simulates the filter that RefreshFavoritesBar applies to populate the combo box.
        /// This keeps the test free of any WinForms dependency.
        /// </summary>
        private static List<MessageTxState> GetFavorites(IEnumerable<MessageTxState> all)
            => all.Where(m => m.IsFavorite).ToList();

        [TestMethod]
        public void FavoritesBar_EmptyWhenNoMessagesAreFavorited()
        {
            var messages = new[] { MakeMessage("A"), MakeMessage("B"), MakeMessage("C") };
            Assert.AreEqual(0, GetFavorites(messages).Count,
                "Favorites list must be empty when no messages are starred.");
        }

        [TestMethod]
        public void FavoritesBar_ContainsOnlyFavoritedMessages()
        {
            var msgA = MakeMessage("ENG_SPEED");
            var msgB = MakeMessage("TRANS_TEMP");
            var msgC = MakeMessage("FUEL_RATE");
            msgA.IsFavorite = true;
            msgC.IsFavorite = true;

            var favs = GetFavorites(new[] { msgA, msgB, msgC });

            Assert.AreEqual(2, favs.Count);
            CollectionAssert.Contains(favs, msgA);
            CollectionAssert.DoesNotContain(favs, msgB);
            CollectionAssert.Contains(favs, msgC);
        }

        [TestMethod]
        public void FavoritesBar_UpdatesAfterUnfavoriting()
        {
            var msgA = MakeMessage("ENG_SPEED");
            var msgB = MakeMessage("TRANS_TEMP");
            msgA.IsFavorite = true;
            msgB.IsFavorite = true;

            // unfavorite msgA
            msgA.IsFavorite = false;

            var favs = GetFavorites(new[] { msgA, msgB });

            Assert.AreEqual(1, favs.Count);
            CollectionAssert.DoesNotContain(favs, msgA);
            CollectionAssert.Contains(favs, msgB);
        }

        [TestMethod]
        public void FavoritesBar_EmptyAfterAllUnfavorited()
        {
            var msgs = new[] { MakeMessage("A"), MakeMessage("B") };
            foreach (var m in msgs) m.IsFavorite = true;
            foreach (var m in msgs) m.IsFavorite = false;

            Assert.AreEqual(0, GetFavorites(msgs).Count,
                "Favorites list must be empty once every message is unstarred.");
        }

        [TestMethod]
        public void FavoritesBar_AllMessagesCanBeFavorited()
        {
            var msgs = Enumerable.Range(1, 5)
                .Select(i => MakeMessage($"MSG_{i}"))
                .ToArray();
            foreach (var m in msgs) m.IsFavorite = true;

            Assert.AreEqual(msgs.Length, GetFavorites(msgs).Count,
                "Every message should appear in the favorites list when all are starred.");
        }

        // ── Enabled/disabled flag is orthogonal to IsFavorite ─────────────────────────────

        [TestMethod]
        public void IsFavorite_IsOrthogonalToEnabled()
        {
            var msgOn  = MakeMessage("ON",  enabled: true);
            var msgOff = MakeMessage("OFF", enabled: false);
            msgOn.IsFavorite  = true;
            msgOff.IsFavorite = true;

            var favs = GetFavorites(new[] { msgOn, msgOff });

            // Both appear in favorites regardless of their Enabled state
            Assert.AreEqual(2, favs.Count,
                "IsFavorite is independent of the Enabled flag; both messages should be in favorites.");
        }

        // ── FavoriteEntry display formatting (mirrors FavoriteEntry.ToString logic) ────────

        private static string FormatFavoriteEntry(MessageTxState msg)
        {
            string idText  = msg.IsExtended ? $"0x{msg.CanId:X8}" : $"0x{msg.CanId:X3}";
            string enabled = msg.Enabled ? string.Empty : " [off]";
            return $"⭐ {msg.Name}  {idText}{enabled}";
        }

        [TestMethod]
        public void FavoriteEntry_ExtendedMessageFormatsCorrectly()
        {
            var msg = MakeMessage("ENG_SPEED", canId: 0x18FD9BFE, isExtended: true, enabled: true);
            string label = FormatFavoriteEntry(msg);
            StringAssert.StartsWith(label, "⭐ ENG_SPEED");
            StringAssert.Contains(label, "0x18FD9BFE");
            Assert.IsFalse(label.Contains("[off]"), "Enabled message must not show [off] suffix.");
        }

        [TestMethod]
        public void FavoriteEntry_StandardFrameFormatsWithShortId()
        {
            var msg = MakeMessage("STD_MSG", canId: 0x123, isExtended: false, enabled: true);
            string label = FormatFavoriteEntry(msg);
            StringAssert.Contains(label, "0x123");
        }

        [TestMethod]
        public void FavoriteEntry_DisabledMessageShowsOffSuffix()
        {
            var msg = MakeMessage("ENG_SPEED", enabled: false);
            msg.IsFavorite = true;
            string label = FormatFavoriteEntry(msg);
            StringAssert.Contains(label, "[off]");
        }

        [TestMethod]
        public void FavoriteEntry_EnabledMessageDoesNotShowOffSuffix()
        {
            var msg = MakeMessage("ENG_SPEED", enabled: true);
            msg.IsFavorite = true;
            string label = FormatFavoriteEntry(msg);
            Assert.IsFalse(label.Contains("[off]"));
        }
    }
}
