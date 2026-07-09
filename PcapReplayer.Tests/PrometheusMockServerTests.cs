using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    [TestClass]
    public class PrometheusMockServerTests
    {
        // ── Golden-format tests: reproduce the real field samples byte-for-byte ──

        [TestMethod]
        public void BuildMetricsBody_NovContainer_MatchesRealFieldSample_RMS01()
        {
            var cfg = new PromMockConfig(
                Port: 9091,
                AssetId: "RMS01",
                EquipmentType: "Pump",       // CAN Generator's own resolved casing (Title Case)
                Manufacturer: "Rolligon",    // ditto
                Ip: "192.168.130.240",
                Crew: "woodlands",
                District: "woodlands",
                TmvAssetId: "tmv_asset_id",
                Version: "70.35.1",
                IsProxyBox: false,
                DirtyValue: 0,
                RespondToRequests: true);

            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            const string expectedLine =
                "pump_rolligon_is_dirty{asset_id=\"RMS01\",crew=\"woodlands\",district=\"woodlands\"," +
                "equipment_type=\"PUMP\",ip=\"192.168.130.240\",mfg=\"ROLLIGON\",port=\"502\"," +
                "protocol=\"MODBUS\",routing_key=\"EQ.PUMP.RMS01.MODBUS\",tmv_asset_id=\"tmv_asset_id\"," +
                "version=\"70.35.1\"} 0";

            StringAssert.Contains(body, expectedLine);
        }

        [TestMethod]
        public void BuildMetricsBody_ProxyBox_MatchesRealFieldSample_MINIPC1()
        {
            var cfg = new PromMockConfig(
                Port: 9091,
                AssetId: "MINIPC1",
                EquipmentType: "Pump",
                Manufacturer: "Rolligon",
                Ip: "192.168.130.137",
                Crew: "woodlands",
                District: "woodlands",
                TmvAssetId: "tmv_asset_id",
                Version: "PB 2.22.0",
                IsProxyBox: true,
                DirtyValue: -999,
                RespondToRequests: true);

            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            const string expectedLine =
                "rolligon_proxybox_config_reported_controller_is_dirty{asset_id=\"MINIPC1\"," +
                "crew=\"woodlands\",district=\"woodlands\",equipment_type=\"PUMP\"," +
                "ip=\"192.168.130.137\",mfg=\"ROLLIGON\",port=\"8000\",protocol=\"HTTP\"," +
                "routing_key=\"EQ.PUMP.MINIPC1.HTTP\",tmv_asset_id=\"tmv_asset_id\"," +
                "url=\"http://192.168.130.137:8000/commands\",version=\"PB 2.22.0\"} -999";

            StringAssert.Contains(body, expectedLine);
        }

        [TestMethod]
        public void BuildMetricsBody_ProxyBox_DirtyValueOne_MatchesRealFieldSample_PAL001()
        {
            var cfg = new PromMockConfig(
                Port: 9091,
                AssetId: "PAL001",
                EquipmentType: "Pump",
                Manufacturer: "Rolligon",
                Ip: "192.168.130.236",
                Crew: "woodlands",
                District: "woodlands",
                TmvAssetId: "tmv_asset_id",
                Version: "PB 2.23.0",
                IsProxyBox: true,
                DirtyValue: 1,
                RespondToRequests: true);

            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            const string expectedLine =
                "rolligon_proxybox_config_reported_controller_is_dirty{asset_id=\"PAL001\"," +
                "crew=\"woodlands\",district=\"woodlands\",equipment_type=\"PUMP\"," +
                "ip=\"192.168.130.236\",mfg=\"ROLLIGON\",port=\"8000\",protocol=\"HTTP\"," +
                "routing_key=\"EQ.PUMP.PAL001.HTTP\",tmv_asset_id=\"tmv_asset_id\"," +
                "url=\"http://192.168.130.236:8000/commands\",version=\"PB 2.23.0\"} 1";

            StringAssert.Contains(body, expectedLine);
        }

        // ── Casing normalization ──────────────────────────────────────────────

        [TestMethod]
        public void BuildMetricsBody_TitleCaseInput_IsUppercasedInLabels()
        {
            // CAN Generator's own resolver produces Title Case ("Pump"/"Rolligon"),
            // but the real field format always uses upper case for these two labels.
            var cfg = MakeConfig(equipmentType: "Pump", manufacturer: "Rolligon", isProxyBox: false);

            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            StringAssert.Contains(body, "equipment_type=\"PUMP\"");
            StringAssert.Contains(body, "mfg=\"ROLLIGON\"");
            StringAssert.DoesNotMatch(body, new System.Text.RegularExpressions.Regex("equipment_type=\"Pump\""));
        }

        [TestMethod]
        public void BuildMetricsBody_RoutingKey_IsAlwaysUppercaseRegardlessOfEquipmentTypeCasing()
        {
            var cfg = MakeConfig(equipmentType: "Blender", manufacturer: "Rolligon", isProxyBox: true, assetId: "B-1");

            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            StringAssert.Contains(body, "routing_key=\"EQ.BLENDER.B-1.HTTP\"");
        }

        // ── Label ordering (real samples are strictly alphabetical) ──────────

        [TestMethod]
        public void BuildMetricsBody_NovContainer_LabelsAreAlphabeticallyOrdered()
        {
            var cfg = MakeConfig(isProxyBox: false);
            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            int iAsset = body.IndexOf("asset_id=");
            int iCrew = body.IndexOf("crew=");
            int iDistrict = body.IndexOf("district=");
            int iEquip = body.IndexOf("equipment_type=");
            int iIp = body.IndexOf("ip=");
            int iMfg = body.IndexOf("mfg=");
            int iPort = body.IndexOf("port=");
            int iProto = body.IndexOf("protocol=");
            int iRouting = body.IndexOf("routing_key=");
            int iTmv = body.IndexOf("tmv_asset_id=");
            int iVersion = body.IndexOf("version=");

            Assert.IsTrue(iAsset < iCrew && iCrew < iDistrict && iDistrict < iEquip && iEquip < iIp &&
                           iIp < iMfg && iMfg < iPort && iPort < iProto && iProto < iRouting &&
                           iRouting < iTmv && iTmv < iVersion,
                "Labels must appear in alphabetical order to match the real field exposition format.");
        }

        [TestMethod]
        public void BuildMetricsBody_ProxyBox_LabelsAreAlphabeticallyOrdered()
        {
            var cfg = MakeConfig(isProxyBox: true);
            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            int iMfg = body.IndexOf("mfg=");
            int iPort = body.IndexOf("port=");
            int iRouting = body.IndexOf("routing_key=");
            int iTmv = body.IndexOf("tmv_asset_id=");
            int iUrl = body.IndexOf("url=");
            int iVersion = body.IndexOf("version=");

            Assert.IsTrue(iMfg < iPort && iPort < iRouting && iRouting < iTmv && iTmv < iUrl && iUrl < iVersion,
                "url must sort between tmv_asset_id and version, matching the real ProxyBox sample.");
        }

        // ── Metric name / port / protocol per flavor ──────────────────────────

        [TestMethod]
        public void BuildMetricsBody_ProxyBox_UsesHttpPortAndProtocolAndHelpType()
        {
            var cfg = MakeConfig(isProxyBox: true);
            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            StringAssert.Contains(body, "# HELP rolligon_proxybox_config_reported_controller_is_dirty");
            StringAssert.Contains(body, "# TYPE rolligon_proxybox_config_reported_controller_is_dirty untyped");
            StringAssert.Contains(body, "rolligon_proxybox_config_reported_controller_is_dirty{");
            StringAssert.Contains(body, "port=\"8000\"");
            StringAssert.Contains(body, "protocol=\"HTTP\"");
            StringAssert.Contains(body, "url=\"http://");
            Assert.IsFalse(body.Contains("pump_rolligon_is_dirty{"), "ProxyBox output must not also emit the MODBUS metric name.");
        }

        [TestMethod]
        public void BuildMetricsBody_NovContainer_UsesModbusPortAndProtocolAndNoUrlLabel()
        {
            var cfg = MakeConfig(isProxyBox: false);
            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            StringAssert.Contains(body, "# HELP pump_rolligon_is_dirty");
            StringAssert.Contains(body, "# TYPE pump_rolligon_is_dirty untyped");
            StringAssert.Contains(body, "pump_rolligon_is_dirty{");
            StringAssert.Contains(body, "port=\"502\"");
            StringAssert.Contains(body, "protocol=\"MODBUS\"");
            Assert.IsFalse(body.Contains("url="), "NOV Container (MODBUS) samples never include a url label.");
            Assert.IsFalse(body.Contains("rolligon_proxybox_config_reported_controller_is_dirty{"),
                "NOV Container output must not also emit the ProxyBox metric name.");
        }

        // ── DirtyValue passthrough ─────────────────────────────────────────────

        [DataTestMethod]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(-999)]
        public void BuildMetricsBody_DirtyValue_IsEmittedVerbatimAsTrailingSampleValue(int dirtyValue)
        {
            var cfg = MakeConfig(dirtyValue: dirtyValue);
            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            StringAssert.Contains(body, $"}} {dirtyValue}\n");
        }

        // ── slot_id golden-format tests: reproduce the real field samples byte-for-byte ──

        [TestMethod]
        public void BuildMetricsBody_SlotId_ProxyBox_MatchesRealFieldSample_PBS006()
        {
            var cfg = MakeSlotConfig(
                assetId: "PBS006", ip: "192.168.130.233", version: "PB 2.21.0",
                slotFlavor: SlotIdFlavor.ProxyBox, slotValue: 11);

            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            const string expectedLine =
                "rolligon_proxybox_config_reported_controller_pump_name{asset_id=\"PBS006\"," +
                "crew=\"woodlands\",district=\"woodlands\",equipment_type=\"PUMP\"," +
                "ip=\"192.168.130.233\",mfg=\"ROLLIGON\",port=\"8000\",protocol=\"HTTP\"," +
                "routing_key=\"EQ.PUMP.PBS006.HTTP\",tmv_asset_id=\"tmv_asset_id\"," +
                "url=\"http://192.168.130.233:8000/commands\",version=\"PB 2.21.0\"} 11";

            StringAssert.Contains(body, expectedLine);
        }

        [TestMethod]
        public void BuildMetricsBody_SlotId_CspPumpV1_MatchesRealFieldSample_99066043()
        {
            var cfg = MakeSlotConfig(
                assetId: "99066043", ip: "192.168.130.211",
                slotFlavor: SlotIdFlavor.CspPumpV1, slotValue: 0);

            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            const string expectedLine =
                "csp_pump_v1_cudd_slot_id{asset_id=\"99066043\",crew=\"woodlands\"," +
                "district=\"woodlands\",equipment_type=\"PUMP\",ip=\"192.168.130.211\"," +
                "mfg=\"CSP\",port=\"502\",protocol=\"MODBUS\"," +
                "routing_key=\"EQ.PUMP.99066043.MODBUS\",tmv_asset_id=\"tmv_asset_id\"," +
                "version=\"V1\"} 0";

            StringAssert.Contains(body, expectedLine);
        }

        [TestMethod]
        public void BuildMetricsBody_SlotId_CspPumpV2_MatchesRealFieldSample_65699()
        {
            var cfg = MakeSlotConfig(
                assetId: "65699", ip: "192.168.130.225",
                slotFlavor: SlotIdFlavor.CspPumpV2, slotValue: 0, engType: "3520");

            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            const string expectedLine =
                "csp_pump_v2_cudd_slot_id{asset_id=\"65699\",crew=\"woodlands\"," +
                "district=\"woodlands\",eng_type=\"3520\",equipment_type=\"PUMP\"," +
                "ip=\"192.168.130.225\",mfg=\"CSP\",port=\"502\",protocol=\"MODBUS\"," +
                "routing_key=\"EQ.PUMP.65699.MODBUS\",tmv_asset_id=\"tmv_asset_id\"," +
                "version=\"V2\"} 0";

            StringAssert.Contains(body, expectedLine);
        }

        [TestMethod]
        public void BuildMetricsBody_SlotId_PumpRolligon_MatchesRealFieldSample_RMS01()
        {
            var cfg = MakeSlotConfig(
                assetId: "RMS01", ip: "192.168.130.240", version: "70.35.1",
                slotFlavor: SlotIdFlavor.PumpRolligon, slotValue: 0);

            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            const string expectedLine =
                "pump_rolligon_slot_id{asset_id=\"RMS01\",crew=\"woodlands\"," +
                "district=\"woodlands\",equipment_type=\"PUMP\",ip=\"192.168.130.240\"," +
                "mfg=\"ROLLIGON\",port=\"502\",protocol=\"MODBUS\"," +
                "routing_key=\"EQ.PUMP.RMS01.MODBUS\",tmv_asset_id=\"tmv_asset_id\"," +
                "version=\"70.35.1\"} 0";

            StringAssert.Contains(body, expectedLine);
        }

        [TestMethod]
        public void BuildMetricsBody_SlotId_Disabled_EmitsOnlyIsDirty()
        {
            var cfg = MakeConfig() with { EnableSlotId = false };
            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            Assert.IsFalse(body.Contains("slot_id"), "slot_id must not appear when EnableSlotId is false.");
            Assert.IsFalse(body.Contains("pump_name"), "slot_id must not appear when EnableSlotId is false.");
        }

        [TestMethod]
        public void BuildMetricsBody_SlotId_CoexistsWithIsDirty_BothLinesPresent()
        {
            var cfg = MakeSlotConfig(slotFlavor: SlotIdFlavor.PumpRolligon, slotValue: 3);
            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            StringAssert.Contains(body, "pump_rolligon_is_dirty{");
            StringAssert.Contains(body, "pump_rolligon_slot_id{");
        }

        [TestMethod]
        public void BuildMetricsBody_SlotId_CspFlavors_UseFixedVersionNotSharedVersionField()
        {
            // CSP's "version" is a fixed product-generation label, not the free-text
            // firmware version shared with ProxyBox/pump_rolligon (e.g. "70.35.1").
            var cfg = MakeSlotConfig(slotFlavor: SlotIdFlavor.CspPumpV1, version: "70.35.1");
            string body = PrometheusMockServer.BuildMetricsBody(cfg);

            int cspLineStart = body.IndexOf("csp_pump_v1_cudd_slot_id{");
            int cspLineEnd = body.IndexOf('\n', cspLineStart);
            string cspLine = body.Substring(cspLineStart, cspLineEnd - cspLineStart);

            StringAssert.Contains(cspLine, "version=\"V1\"");
            Assert.IsFalse(cspLine.Contains("70.35.1"),
                "The csp_pump_v1 line must use its fixed 'V1' version, not the shared Version field (which is only for ProxyBox/pump_rolligon).");
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static PromMockConfig MakeConfig(
            string assetId = "RMS01",
            string equipmentType = "Pump",
            string manufacturer = "Rolligon",
            string ip = "192.168.130.240",
            bool isProxyBox = false,
            int dirtyValue = 0) => new(
                Port: 9091,
                AssetId: assetId,
                EquipmentType: equipmentType,
                Manufacturer: manufacturer,
                Ip: ip,
                Crew: "woodlands",
                District: "woodlands",
                TmvAssetId: "tmv_asset_id",
                Version: "70.35.1",
                IsProxyBox: isProxyBox,
                DirtyValue: dirtyValue,
                RespondToRequests: true);

        private static PromMockConfig MakeSlotConfig(
            string assetId = "RMS01",
            string ip = "192.168.130.240",
            string version = "70.35.1",
            SlotIdFlavor slotFlavor = SlotIdFlavor.PumpRolligon,
            int slotValue = 0,
            string engType = "3520") =>
            MakeConfig(assetId: assetId, ip: ip, isProxyBox: slotFlavor == SlotIdFlavor.ProxyBox) with
            {
                Version = version,
                EnableSlotId = true,
                SlotFlavor = slotFlavor,
                SlotIdValue = slotValue,
                EngType = engType
            };
    }
}
