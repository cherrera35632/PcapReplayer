using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace PcapReplayer
{
    public partial class MainForm
    {
        // ── is_dirty Prometheus Mock tab ──────────────────────────────────────
        private GroupBox   grpPromMock          = null!;
        private CheckBox   chkEnablePromMock    = null!;
        private CheckBox   chkPromRespondToReq  = null!;
        private TextBox    txtPromMockPort      = null!;
        private RadioButton radProxyBox         = null!;
        private RadioButton radNovContainer     = null!;
        private ComboBox   cboDirtyState        = null!;
        private TextBox    txtPromCrew          = null!;
        private TextBox    txtPromDistrict      = null!;
        private TextBox    txtPromTmvAssetId    = null!;
        private TextBox    txtPromVersion       = null!;
        private Label      lblPromIdentity      = null!;
        private Label      lblPromMockStatus    = null!;
        private TextBox    txtPromMetricPreview = null!;
        private ListBox    lstPromRequestLog    = null!;

        private PrometheusMockServer _promMockServer = null!;

        // Mirrors UDPCANGateway.App/default_config.json's EquipmentType/Manufacturer
        // tables — keep in sync if that config changes. Values are the canonical
        // (resolved) names; keys of the lookup are the short codes used in the
        // CAN Generator's "USR Header" field (AssetId|EquipType|Mfg|...).
        private static readonly Dictionary<string, string> _equipTypeCodes =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["P"] = "Pump",
                ["B"] = "Blender",
                ["BP"] = "Boost Pump",
                ["BoostPump"] = "Boost Pump",
                ["L"] = "LAS",
                ["H"] = "HAS",
                ["D"] = "DAS",
            };

        private static readonly Dictionary<string, string> _mfgCodes =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["CAT"] = "CATERPILLAR",
                ["C"] = "CSP",
                ["CCS&P"] = "CSP",
                ["CS&P"] = "CSP",
                ["R"] = "Rolligon",
            };

        private static string ResolveCode(string code, Dictionary<string, string> table) =>
            !string.IsNullOrWhiteSpace(code) && table.TryGetValue(code.Trim(), out var resolved)
                ? resolved
                : $"*UNK_{code}";

        private TabPage BuildIsDirtyMockTab()
        {
            var tab = new TabPage("🧪  is_dirty Mock") { Padding = new Padding(6) };

            _promMockServer = new PrometheusMockServer();
            _promMockServer.OnStatusChanged += msg => SetPromMockStatus(msg);
            _promMockServer.OnRequestLogged += line => AppendPromRequestLog(line);

            tab.Controls.Add(BuildPromMockGroup());
            return tab;
        }

        private GroupBox BuildPromMockGroup()
        {
            grpPromMock = new GroupBox
            {
                Text      = "🧪  is_dirty Prometheus Mock  —  local simulation only",
                Location  = new Point(8, 8),
                Size      = new Size(648, 700),
                Font      = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.SteelBlue
            };

            int col1 = 12, col2 = 320;
            int y = 22;

            var lblInfo = new Label
            {
                Text = "is_dirty arrives in the field via ProxyBox HTTP polling or NOV Container\n" +
                       "MODBUS — never over CAN, so nothing else in this tool can generate it.\n" +
                       "Metric names/labels below match the real field format exactly, so a\n" +
                       "dashboard built against this mock needs no changes once swapped to the\n" +
                       "real exporter.",
                Location  = new Point(col1, y),
                Size      = new Size(624, 62),
                Font      = new Font("Segoe UI", 8.5f, FontStyle.Italic),
                ForeColor = Color.Gray
            };
            grpPromMock.Controls.Add(lblInfo);
            y += 68;

            // ── Identity (synced from CAN Generator tab) ─────────────────────
            AddSectionHeader(grpPromMock, col1, y, "Identity  —  synced live from the CAN Generator tab"); y += 26;

            lblPromIdentity = new Label
            {
                Text      = "(waiting for CAN Generator USR Header...)",
                Location  = new Point(col1, y),
                Size      = new Size(624, 36),
                Font      = new Font("Consolas", 8.5f),
                ForeColor = Color.DimGray
            };
            grpPromMock.Controls.Add(lblPromIdentity);
            y += 42;

            // ── Pump hardware flavor ──────────────────────────────────────────
            AddSectionHeader(grpPromMock, col1, y, "Pump Hardware Flavor"); y += 26;

            radProxyBox = new RadioButton
            {
                Text = "ProxyBox  (HTTP, port 8000)", Checked = true,
                Location = new Point(col1, y), AutoSize = true
            };
            radNovContainer = new RadioButton
            {
                Text = "NOV Container  (MODBUS, port 502)",
                Location = new Point(col2, y), AutoSize = true
            };
            radProxyBox.CheckedChanged     += (s, e) => { OnFlavorChanged(); RefreshPromPreview(); };
            radNovContainer.CheckedChanged += (s, e) => RefreshPromPreview();
            grpPromMock.Controls.Add(radProxyBox);
            grpPromMock.Controls.Add(radNovContainer);
            y += 32;

            // ── Simulated state ───────────────────────────────────────────────
            AddSectionHeader(grpPromMock, col1, y, "Simulated State"); y += 26;

            grpPromMock.Controls.Add(new Label
            {
                Text = "Dirty State:", Location = new Point(col1, y + 3), AutoSize = true
            });
            cboDirtyState = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Location = new Point(col1, y + 20),
                Width = 200
            };
            cboDirtyState.Items.AddRange(new object[] { "Clean (0)", "Dirty (1)", "Unknown (-999)" });
            cboDirtyState.SelectedIndex = 0;
            cboDirtyState.SelectedIndexChanged += (s, e) => RefreshPromPreview();
            grpPromMock.Controls.Add(cboDirtyState);
            y += 44;

            // ── Extra labels (not present on the CAN Generator tab) ──────────
            AddSectionHeader(grpPromMock, col1, y, "Extra Labels"); y += 26;

            AddInner(grpPromMock, "Crew:", col1, y, out txtPromCrew, "woodlands", w: 140);
            AddInner(grpPromMock, "District:", col2, y, out txtPromDistrict, "woodlands", w: 140);
            y += 44;

            AddInner(grpPromMock, "TMV Asset Id:", col1, y, out txtPromTmvAssetId, "tmv_asset_id", w: 140);
            AddInner(grpPromMock, "Version:", col2, y, out txtPromVersion, "PB 2.23.0", w: 140);
            y += 44;

            txtPromCrew.TextChanged       += (s, e) => RefreshPromPreview();
            txtPromDistrict.TextChanged   += (s, e) => RefreshPromPreview();
            txtPromTmvAssetId.TextChanged += (s, e) => RefreshPromPreview();
            txtPromVersion.TextChanged    += (s, e) => RefreshPromPreview();

            // ── Server ────────────────────────────────────────────────────────
            AddSectionHeader(grpPromMock, col1, y, "Server"); y += 26;

            chkEnablePromMock = new CheckBox
            {
                Text = "Enable Prometheus Mock Server", Location = new Point(col1, y), AutoSize = true
            };
            chkEnablePromMock.CheckedChanged += ChkEnablePromMock_CheckedChanged;

            chkPromRespondToReq = new CheckBox
            {
                Text = "Respond to Requests  (uncheck → 503)",
                Location = new Point(col2, y), AutoSize = true,
                Checked = true, Enabled = false
            };
            y += 24;

            AddInner(grpPromMock, "Port:", col1, y, out txtPromMockPort, "9091", w: 70);
            txtPromMockPort.TextChanged += (s, e) => RefreshPromPreview();
            y += 44;

            lblPromMockStatus = new Label
            {
                Text = "Stopped", Location = new Point(col1, y),
                AutoSize = true, ForeColor = Color.DimGray,
                Font = new Font("Consolas", 9f)
            };
            y += 28;

            // ── Live preview ──────────────────────────────────────────────────
            AddSectionHeader(grpPromMock, col1, y, "Live Metric Preview  —  exactly what Prometheus will scrape"); y += 26;

            txtPromMetricPreview = new TextBox
            {
                Location = new Point(col1, y), Width = 622, Height = 70,
                Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8f), BackColor = Color.FromArgb(245, 245, 245)
            };
            y += 76;

            // ── Incoming requests ─────────────────────────────────────────────
            AddSectionHeader(grpPromMock, col1, y, "Incoming Requests"); y += 26;

            lstPromRequestLog = new ListBox
            {
                Location = new Point(col1, y), Width = 622, Height = 90,
                Font = new Font("Consolas", 8.5f),
                HorizontalScrollbar = true, ScrollAlwaysVisible = true
            };
            var btnPromClear = new Button
            {
                Text = "Clear Log", Location = new Point(col1, y + 95), Width = 80, Height = 24
            };
            btnPromClear.Click += (s, e) => lstPromRequestLog.Items.Clear();

            grpPromMock.Controls.AddRange(new Control[]
            {
                chkEnablePromMock, chkPromRespondToReq, lblPromMockStatus,
                txtPromMetricPreview, lstPromRequestLog, btnPromClear
            });

            // Keep the identity label / preview live as the CAN Generator tab changes.
            txtCanUsrHeader.TextChanged  += (s, e) => RefreshPromPreview();
            txtCanSourceIp.TextChanged   += (s, e) => RefreshPromPreview();

            RefreshPromPreview();

            return grpPromMock;
        }

        private void OnFlavorChanged()
        {
            // Swap in a sensible default version string per flavor; user can still edit freely.
            txtPromVersion.Text = radProxyBox.Checked ? "PB 2.23.0" : "70.35.1";
        }

        /// <summary>Parses the CAN Generator's "AssetId|EquipType|Mfg|..." header the same way
        /// UDPCANGateway resolves it, so this mock's identity always matches whatever
        /// can_message_counter labels the CAN Generator is currently producing.</summary>
        private (string assetId, string equipType, string mfg) ParseCanGenIdentity()
        {
            string header = txtCanUsrHeader?.Text ?? "";
            string[] parts = header.Split('|');

            string assetId = parts.Length > 0 ? parts[0].Trim() : "";
            string equipRaw = parts.Length > 1 ? parts[1].Trim() : "";
            string mfgRaw = parts.Length > 2 ? parts[2].Trim() : "";

            string equipType = string.IsNullOrWhiteSpace(equipRaw) ? "*UNK_" : ResolveCode(equipRaw, _equipTypeCodes);
            string mfg = string.IsNullOrWhiteSpace(mfgRaw) ? "*UNK_" : ResolveCode(mfgRaw, _mfgCodes);

            return (assetId, equipType, mfg);
        }

        private PromMockConfig GetCurrentPromMockConfig()
        {
            var (assetId, equipType, mfg) = ParseCanGenIdentity();
            string ip = txtCanSourceIp?.Text?.Trim() ?? "127.0.0.2";

            int dirtyValue = cboDirtyState.SelectedIndex switch
            {
                0 => 0,
                1 => 1,
                _ => -999
            };

            return new PromMockConfig(
                Port: int.TryParse(txtPromMockPort.Text, out int p) ? p : 9091,
                AssetId: assetId,
                EquipmentType: equipType,
                Manufacturer: mfg,
                Ip: ip,
                Crew: txtPromCrew.Text.Trim(),
                District: txtPromDistrict.Text.Trim(),
                TmvAssetId: txtPromTmvAssetId.Text.Trim(),
                Version: txtPromVersion.Text.Trim(),
                IsProxyBox: radProxyBox.Checked,
                DirtyValue: dirtyValue,
                RespondToRequests: chkPromRespondToReq.Checked);
        }

        private void RefreshPromPreview()
        {
            if (lblPromIdentity == null || txtPromMetricPreview == null) return;

            var (assetId, equipType, mfg) = ParseCanGenIdentity();
            bool unresolved = equipType.StartsWith("*UNK_") || mfg.StartsWith("*UNK_");

            lblPromIdentity.Text =
                $"AssetId: {(string.IsNullOrEmpty(assetId) ? "(none)" : assetId)}   " +
                $"EquipmentType: {equipType}   Manufacturer: {mfg}   Ip: {txtCanSourceIp?.Text}";
            lblPromIdentity.ForeColor = unresolved ? Color.Crimson : Color.DimGray;

            txtPromMetricPreview.Text = PrometheusMockServer.BuildMetricsBody(GetCurrentPromMockConfig());
        }

        private void ChkEnablePromMock_CheckedChanged(object? sender, EventArgs e)
        {
            if (chkEnablePromMock.Checked)
            {
                if (!int.TryParse(txtPromMockPort.Text, out int port) || port < 1 || port > 65535)
                {
                    MessageBox.Show("Please enter a valid port number (1-65535).", "Invalid Port",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    chkEnablePromMock.Checked = false;
                    return;
                }
                _promMockServer.Start(port, "127.0.0.1", GetCurrentPromMockConfig);
                chkPromRespondToReq.Enabled = true;
            }
            else
            {
                _promMockServer.Stop();
                chkPromRespondToReq.Enabled = false;
                chkPromRespondToReq.Checked = true;
            }
        }

        private void SetPromMockStatus(string msg)
        {
            if (this.InvokeRequired) { this.Invoke(() => SetPromMockStatus(msg)); return; }
            lblPromMockStatus.Text = msg;
            lblPromMockStatus.ForeColor = msg.StartsWith("Listening") ? Color.DarkGreen
                                        : msg.StartsWith("Error") ? Color.Crimson
                                        : Color.DimGray;
        }

        private void AppendPromRequestLog(string line)
        {
            if (this.InvokeRequired) { this.Invoke(() => AppendPromRequestLog(line)); return; }
            if (lstPromRequestLog.Items.Count >= 200) lstPromRequestLog.Items.RemoveAt(0);
            lstPromRequestLog.Items.Add(line);
            lstPromRequestLog.TopIndex = lstPromRequestLog.Items.Count - 1;
        }
    }
}
