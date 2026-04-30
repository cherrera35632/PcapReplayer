using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PcapReplayer
{
    public class MainForm : Form
    {
        // ── Replay tab ────────────────────────────────────────────────────────
        private TextBox    txtPcapPath   = null!;
        private TextBox    txtTargetIp   = null!;
        private TextBox    txtSourceIp   = null!;
        private TextBox    txtTargetPort = null!;
        private TextBox    txtSpeed      = null!;
        private RichTextBox txtLog       = null!;
        private CheckBox   chkLoop       = null!;
        private Button     btnStop       = null!;
        private Button     btnStart      = null!;
        private Button     btnBrowse     = null!;
        private Label      lblDetection  = null!;

        // ── USR Override panel ────────────────────────────────────────────────
        private GroupBox   grpUsr              = null!;
        private CheckBox   chkUsrOverride      = null!;
        private TextBox    txtUsrMetadata      = null!;
        private Label      lblUsrCharCount     = null!;

        // ── PEAK Mock panel ───────────────────────────────────────────────────
        private GroupBox   grpPeak             = null!;
        private CheckBox   chkEnableMock       = null!;
        private CheckBox   chkRespondToReq     = null!;
        private TextBox    txtMockPort         = null!;
        private CheckBox   chkMatchSourceIp    = null!;
        private TextBox    txtCustomListenerIp = null!;
        private ComboBox   cboProductName      = null!;
        private ComboBox   cboOrderNo          = null!;
        private TextBox    txtDeviceName       = null!;
        private Label      lblDeviceNameCount  = null!;
        private ComboBox   cboCanCount         = null!;
        private ComboBox   cboChannelName      = null!;
        private Label      lblChannelNameCount = null!;
        private ComboBox   cboBitrate          = null!;
        private ComboBox   cboActive           = null!;
        private ComboBox   cboListenOnly       = null!;
        private Label      lblServerStatus     = null!;
        private ListBox    lstRequestLog       = null!;

        // ── TRC Converter tab ─────────────────────────────────────────────────
        private TextBox    txtTrcPath       = null!;
        private TextBox    txtTrcOutputDir  = null!;
        private Label      lblTrcOutputName = null!;
        private TextBox    txtTrcAssetId    = null!;
        private TextBox    txtTrcEquipType  = null!;
        private TextBox    txtTrcMfg        = null!;
        private TextBox    txtTrcDatabase   = null!;
        private TextBox    txtTrcCanName    = null!;
        private Label      lblTrcAssembled  = null!;
        private TextBox    txtTrcSourceIP   = null!;
        private TextBox    txtTrcDestIP     = null!;
        private TextBox    txtTrcDestPort   = null!;
        private TextBox    txtTrcFramesPkt  = null!;
        private TextBox    txtTrcBatchMs    = null!;
        private Button     btnTrcConvert    = null!;
        private Button     btnTrcLoadReplay = null!;
        private RichTextBox txtTrcLog       = null!;
        private string?    _lastConvertedPcap;

        // ── Engine & server / shared ──────────────────────────────────────────
        // Typed to IReplayEngine (Dependency Inversion) — MainForm never references
        // the concrete class. A CLI host or test can inject any IReplayEngine.
        private IReplayEngine      _engine     = null!;
        private MetadataMockServer _mockServer = null!;
        private PcapAnalysisResult? _lastAnalysis;
        private TabControl         _tabs       = null!;

        // ── Character limits ──────────────────────────────────────────────────
        private const int USR_META_MAX   = 40;
        private const int PEAK_NAME_MAX  = 50;
        private const int PEAK_NOTES_MAX = 125;

        // ── Constructor ───────────────────────────────────────────────────────
        public MainForm()
        {
            this.Text        = "Pcap Replayer Tool";
            this.Size        = new Size(680, 790);
            this.MinimumSize = new Size(680, 790);
            this.StartPosition = FormStartPosition.CenterScreen;

            var tabs = new TabControl { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9f) };
            tabs.TabPages.Add(BuildReplayTab());
            tabs.TabPages.Add(BuildMetadataTab());
            tabs.TabPages.Add(BuildTrcTab());
            this.Controls.Add(tabs);
            _tabs = tabs;

            // Engine
            _engine = new ReplayEngine();
            _engine.OnLog      += Log;
            _engine.OnProgress += count => { if (count % 1000 == 0) Log($"Sent {count} packets..."); };
            _engine.OnComplete += () => { Log("Replay finished!"); EnableReplayControls(true); };
            _engine.OnError    += ex => { Log($"Error: {ex.Message}"); EnableReplayControls(true); };

            // Mock server
            _mockServer = new MetadataMockServer();
            _mockServer.OnStatusChanged  += msg  => SetMockStatus(msg);
            _mockServer.OnRequestLogged  += line => AppendRequestLog(line);

            this.FormClosing += (s, e) => _mockServer.Stop();
        }

        // ══════════════════════════════════════════════════════════════════════
        //  REPLAY TAB
        // ══════════════════════════════════════════════════════════════════════
        private TabPage BuildReplayTab()
        {
            var tab = new TabPage("📡  Replay") { Padding = new Padding(10) };

            // PCAP file row
            var lblPath = new Label { Text = "PCAP File:", Location = new Point(10, 18), AutoSize = true };
            txtPcapPath = new TextBox { Location = new Point(10, 40), Width = 520, ReadOnly = true };
            btnBrowse   = new Button  { Text = "...", Location = new Point(536, 39), Width = 40 };
            btnBrowse.Click += BtnBrowse_Click;

            // Source / Target row
            var lblSrc  = new Label { Text = "🚩 Source IP:",  Location = new Point(10,  78), AutoSize = true };
            txtSourceIp = new TextBox { Text = "127.0.0.2",    Location = new Point(10,  98), Width = 110 };

            var lblIp   = new Label { Text = "🎯 Target IP:",  Location = new Point(130, 78), AutoSize = true };
            txtTargetIp = new TextBox { Text = "127.0.0.1",    Location = new Point(130, 98), Width = 110 };

            var lblPort  = new Label { Text = "Override Port:", Location = new Point(250, 78), AutoSize = true };
            txtTargetPort = new TextBox { PlaceholderText = "Auto", Location = new Point(250, 98), Width = 80 };

            var lblSpeed = new Label { Text = "Speed (x):",    Location = new Point(340, 78), AutoSize = true };
            txtSpeed     = new TextBox { Text = "1.0",          Location = new Point(340, 98), Width = 50 };

            chkLoop  = new CheckBox { Text = "Loop", Location = new Point(400, 100), AutoSize = true };

            btnStart = new Button
            {
                Text = "▶  Start Replay", Location = new Point(430, 130), Width = 130,
                BackColor = Color.FromArgb(144, 238, 144), FlatStyle = FlatStyle.Flat
            };
            btnStart.Click += BtnStart_Click;

            btnStop = new Button
            {
                Text = "■  Stop", Location = new Point(570, 130), Width = 70,
                BackColor = Color.FromArgb(255, 160, 122), FlatStyle = FlatStyle.Flat, Enabled = false
            };
            btnStop.Click += (s, e) => _engine.Stop();

            // Detection banner
            lblDetection = new Label
            {
                Text      = "No file loaded.",
                Location  = new Point(10, 135),
                AutoSize  = false,
                Size      = new Size(415, 22),
                ForeColor = Color.DimGray,
                Font      = new Font("Segoe UI", 8.5f, FontStyle.Italic)
            };

            txtLog = new RichTextBox
            {
                Location    = new Point(10, 165),
                Width       = 634,
                Height      = 550,
                ReadOnly    = true,
                Font        = new Font("Consolas", 9),
                ScrollBars  = RichTextBoxScrollBars.Vertical,
                BackColor   = Color.FromArgb(20, 20, 20),
                ForeColor   = Color.LightGray
            };

            tab.Controls.AddRange(new Control[]
            {
                lblPath, txtPcapPath, btnBrowse,
                lblSrc, txtSourceIp, lblIp, txtTargetIp,
                lblPort, txtTargetPort, lblSpeed, txtSpeed, chkLoop,
                btnStart, btnStop, lblDetection, txtLog
            });

            return tab;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  METADATA TAB
        // ══════════════════════════════════════════════════════════════════════
        private TabPage BuildMetadataTab()
        {
            var tab  = new TabPage("🖥️  Metadata Mock") { Padding = new Padding(6) };

            tab.Controls.Add(BuildUsrGroup());
            tab.Controls.Add(BuildPeakGroup());

            return tab;
        }

        // ── USR Override GroupBox ─────────────────────────────────────────────
        private GroupBox BuildUsrGroup()
        {
            grpUsr = new GroupBox
            {
                Text     = "🔌  USR-CANET200 Metadata Override",
                Location = new Point(8, 8),
                Size     = new Size(648, 118),
                Font     = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.SteelBlue
            };

            chkUsrOverride = new CheckBox
            {
                Text     = "Override USR Metadata String  (injected into every USR payload before sending)",
                Location = new Point(10, 22),
                AutoSize = true,
                Font     = new Font("Segoe UI", 9f)
            };
            chkUsrOverride.CheckedChanged += (s, e) =>
            {
                // Only controls the TextBox enabled state.
                // The transformer is built fresh from the current checkbox state on each Start.
                txtUsrMetadata.Enabled = chkUsrOverride.Checked;
            };

            var lblStr = new Label
            {
                Text     = $"Identity string  (max {USR_META_MAX} chars — USR-CANET200 hardware limit):",
                Location = new Point(10, 46),
                AutoSize = true,
                Font     = new Font("Segoe UI", 8.5f)
            };

            txtUsrMetadata = new TextBox
            {
                Text     = "",
                Location = new Point(10, 63),
                Width    = 510,
                Enabled  = false,
                Font     = new Font("Consolas", 9f)
            };
            txtUsrMetadata.TextChanged += TxtUsrMetadata_TextChanged;

            lblUsrCharCount = new Label
            {
                Text      = $"0 / {USR_META_MAX}",
                Location  = new Point(526, 66),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 8.5f),
                ForeColor = Color.DimGray
            };

            var lblHint = new Label
            {
                Text      = "Format:  AssetId | EquipType | Mfg | Database | CANName | HardwareTypeId   (field 6 optional)",
                Location  = new Point(10, 92),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 8f),
                ForeColor = Color.Gray
            };

            grpUsr.Controls.AddRange(new Control[]
            {
                chkUsrOverride, lblStr, txtUsrMetadata, lblUsrCharCount, lblHint
            });

            return grpUsr;
        }

        // ── PEAK Mock GroupBox ────────────────────────────────────────────────
        private GroupBox BuildPeakGroup()
        {
            grpPeak = new GroupBox
            {
                Text      = "📡  PEAK CAN Gateway Mock Server",
                Location  = new Point(8, 133),
                Size      = new Size(648, 602),
                Font      = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.SteelBlue
            };

            int col1 = 12, col2 = 320;
            int y = 22;

            // ── Enable / Respond ──────────────────────────────────────────────
            chkEnableMock = new CheckBox
            {
                Text     = "Enable Metadata Mock Server",
                Location = new Point(col1, y),
                AutoSize = true,
                Font     = new Font("Segoe UI", 9f, FontStyle.Regular)
            };
            chkEnableMock.CheckedChanged += ChkEnableMock_CheckedChanged;

            chkRespondToReq = new CheckBox
            {
                Text     = "Respond to Requests  (uncheck → 503)",
                Location = new Point(col2, y),
                AutoSize = true,
                Checked  = true,
                Enabled  = false,
                Font     = new Font("Segoe UI", 9f, FontStyle.Regular)
            };
            y += 30;

            // ── Server section ────────────────────────────────────────────────
            AddSectionHeader(grpPeak, col1, y, "Server"); y += 26;

            AddInner(grpPeak, "HTTP Port:", col1, y, out txtMockPort, "35250", w: 70);

            chkMatchSourceIp = new CheckBox
            {
                Text     = "Match Source IP from Replay tab",
                Location = new Point(col2, y + 20),
                AutoSize = true,
                Checked  = true,
                Font     = new Font("Segoe UI", 9f, FontStyle.Regular)
            };
            txtCustomListenerIp = new TextBox
            {
                Text    = "127.0.0.1",
                Location = new Point(col2, y + 18),
                Width   = 110,
                Visible = false
            };
            chkMatchSourceIp.CheckedChanged += (s, e) =>
            {
                txtCustomListenerIp.Visible  = !chkMatchSourceIp.Checked;
                chkMatchSourceIp.Location    = chkMatchSourceIp.Checked
                    ? new Point(col2, y + 20)
                    : new Point(col2, y + 44);
            };
            grpPeak.Controls.Add(chkMatchSourceIp);
            grpPeak.Controls.Add(txtCustomListenerIp);
            y += 44;

            // ── Device section ────────────────────────────────────────────────
            AddSectionHeader(grpPeak, col1, y, "Device  —  cmd = get device"); y += 26;

            AddComboInner(grpPeak, "Product Name:", col1, y, out cboProductName,
                new[] { "PCAN-Gateway DR", "PCAN-Gateway FD" }, 0);
            var tipOrder = new ToolTip();
            AddComboInner(grpPeak, "Order Number:", col2, y, out cboOrderNo,
                new[] { "IPEH-004010", "IPEH-004011" }, 0);
            tipOrder.SetToolTip(cboOrderNo, "Must contain IPEH-004010 for UDPCANGateway to accept.");
            y += 44;

            AddInner(grpPeak, $"Device Name  (max {PEAK_NAME_MAX} chars):", col1, y, out txtDeviceName,
                "9991119999,Pump,Rolligon", w: 230);
            txtDeviceName.TextChanged += TxtDeviceName_TextChanged;

            lblDeviceNameCount = new Label
            {
                Text      = $"0 / {PEAK_NAME_MAX}",
                Location  = new Point(col1 + 234, y + 21),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 8f),
                ForeColor = Color.DimGray
            };
            grpPeak.Controls.Add(lblDeviceNameCount);

            AddComboInner(grpPeak, "CAN Count:", col2, y, out cboCanCount, new[] { "1", "2" }, 1);
            y += 44;

            // ── CAN Channel section ───────────────────────────────────────────
            AddSectionHeader(grpPeak, col1, y, "CAN Channel 0  —  cmd = get can 0"); y += 26;

            grpPeak.Controls.Add(new Label
            {
                Text     = $"Channel Name / user_notes  (max {PEAK_NOTES_MAX} chars):",
                Location = new Point(col1, y + 3),
                AutoSize = true,
                Font     = new Font("Segoe UI", 9f, FontStyle.Regular)
            });

            cboChannelName = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDown,
                MaxLength     = PEAK_NOTES_MAX,
                Location      = new Point(col1, y + 20),
                Width         = 240,
                Font          = new Font("Segoe UI", 9f, FontStyle.Regular)
            };
            cboChannelName.Items.AddRange(new[]
            {
                "rolligon_pump__1,novpump__1,j1939__1,j1939_73_dtc__1|C1",
                "rolligon_pump__1,novpump__1,j1939__1,j1939_73_dtc__1|C2",
                "J0|C1", "J0|C2", "J0,JD0|C1", "CAN_ONE", "CAN_TWO"
            });
            cboChannelName.SelectedIndex = 0;
            cboChannelName.TextChanged   += CboChannelName_TextChanged;
            grpPeak.Controls.Add(cboChannelName);

            lblChannelNameCount = new Label
            {
                Text      = $"0 / {PEAK_NOTES_MAX}",
                Location  = new Point(col1 + 244, y + 23),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 8f),
                ForeColor = Color.DimGray
            };
            grpPeak.Controls.Add(lblChannelNameCount);

            AddComboInner(grpPeak, "Bitrate:", col2, y, out cboBitrate,
                new[] { "125000", "250000", "500000", "1000000" }, 1);
            y += 44;

            AddComboInner(grpPeak, "Active:", col1, y, out cboActive, new[] { "0", "1" }, 1);
            AddComboInner(grpPeak, "Listen Only:", col2, y, out cboListenOnly, new[] { "0", "1" }, 0);
            y += 44;

            // ── Status ────────────────────────────────────────────────────────
            AddSectionHeader(grpPeak, col1, y, "Status"); y += 26;

            lblServerStatus = new Label
            {
                Text      = "Stopped",
                Location  = new Point(col1, y),
                AutoSize  = true,
                ForeColor = Color.DimGray,
                Font      = new Font("Consolas", 9f, FontStyle.Regular)
            };
            y += 28;

            // ── Incoming Requests ─────────────────────────────────────────────
            AddSectionHeader(grpPeak, col1, y, "Incoming Requests"); y += 26;

            lstRequestLog = new ListBox
            {
                Location            = new Point(col1, y),
                Width               = 622,
                Height              = 130,
                Font                = new Font("Consolas", 8.5f),
                HorizontalScrollbar = true,
                ScrollAlwaysVisible = true
            };

            var btnClear = new Button
            {
                Text     = "Clear Log",
                Location = new Point(col1, y + 135),
                Width    = 80, Height = 24
            };
            btnClear.Click += (s, e) => lstRequestLog.Items.Clear();

            grpPeak.Controls.AddRange(new Control[]
            {
                chkEnableMock, chkRespondToReq,
                lblServerStatus,
                lstRequestLog, btnClear
            });

            // Trigger initial char counts
            TxtDeviceName_TextChanged(null, EventArgs.Empty);
            CboChannelName_TextChanged(null, EventArgs.Empty);

            return grpPeak;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  BROWSE + PCAP ANALYSIS
        // ══════════════════════════════════════════════════════════════════════
        private async void BtnBrowse_Click(object? sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog { Filter = "PCAP Files|*.pcap;*.pcapng|All Files|*.*" };
            if (ofd.ShowDialog() != DialogResult.OK) return;

            txtPcapPath.Text = ofd.FileName;
            lblDetection.Text      = "🔍 Analysing...";
            lblDetection.ForeColor = Color.DarkOrange;

            Log($"📂 Loaded: {System.IO.Path.GetFileName(ofd.FileName)}");
            Log($"🔍 Scanning first {PcapAnalyzer.MAX_PACKETS_TO_SCAN} UDP packets...");

            _lastAnalysis = await PcapAnalyzer.AnalyseAsync(ofd.FileName);
            ApplyDetectionResult(_lastAnalysis);
        }

        private void ApplyDetectionResult(PcapAnalysisResult r)
        {
            // ── Console summary ───────────────────────────────────────────────
            switch (r.Protocol)
            {
                case DetectedProtocol.USR:
                    Log($"✅ Detected: USR-CANET200 Format  ({r.UsrPacketsFound} USR packets, {r.PeakPacketsFound} PEAK packets)");
                    foreach (var ep in r.SourceEndpoints) Log($"   Source endpoint: {ep}");
                    if (r.DetectedUsrMetadataString != null)
                        Log($"   Metadata string found in capture: {r.DetectedUsrMetadataString}");
                    Log("   ℹ️  PEAK Mock Server section grayed out.");
                    break;

                case DetectedProtocol.PEAK:
                    Log($"✅ Detected: PEAK CAN Format  ({r.UsrPacketsFound} USR packets, {r.PeakPacketsFound} PEAK packets)");
                    foreach (var ep in r.SourceEndpoints) Log($"   Source endpoint: {ep}");
                    Log("   ℹ️  USR Metadata Override section grayed out.");
                    break;

                case DetectedProtocol.Mixed:
                    Log($"⚠️  Detected: MIXED — USR + PEAK traffic  (USR: {r.UsrPacketsFound}, PEAK: {r.PeakPacketsFound})");
                    foreach (var ep in r.SourceEndpoints) Log($"   Endpoint: {ep}");
                    Log("   ℹ️  Both sections are active.");
                    break;

                default:
                    Log($"❓ Detection inconclusive after scanning {r.TotalUdpPacketsScanned} UDP packets.");
                    Log("   Both sections remain active.");
                    break;
            }

            // ── Adaptive UI ───────────────────────────────────────────────────
            bool usrActive  = r.Protocol is DetectedProtocol.USR or DetectedProtocol.Mixed or DetectedProtocol.Unknown;
            bool peakActive = r.Protocol is DetectedProtocol.PEAK or DetectedProtocol.Mixed or DetectedProtocol.Unknown;

            grpUsr.Enabled  = usrActive;
            grpPeak.Enabled = peakActive;

            // Update detection banner in Replay tab
            (lblDetection.Text, lblDetection.ForeColor) = r.Protocol switch
            {
                DetectedProtocol.USR     => ("✅  USR-CANET200 detected", Color.Green),
                DetectedProtocol.PEAK    => ("✅  PEAK CAN Gateway detected", Color.Green),
                DetectedProtocol.Mixed   => ("⚠️  Mixed: USR + PEAK traffic", Color.DarkOrange),
                _                        => ("❓  Format unknown — both sections active", Color.DimGray)
            };

            // Pre-populate USR metadata field from PCAP
            if (r.DetectedUsrMetadataString != null && usrActive)
            {
                txtUsrMetadata.Text = r.DetectedUsrMetadataString;
                Log($"   ✏️  USR Override pre-populated from capture.");
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        //  CHARACTER COUNT VALIDATORS
        // ══════════════════════════════════════════════════════════════════════
        private void TxtUsrMetadata_TextChanged(object? sender, EventArgs e)
        {
            int len = txtUsrMetadata.Text.Length;
            lblUsrCharCount.Text      = $"{len} / {USR_META_MAX}";
            lblUsrCharCount.ForeColor = len > USR_META_MAX ? Color.Crimson : Color.DimGray;
            // No live sync to engine — transformer is built from current text on each Start.
            if (len > USR_META_MAX)
                lblUsrCharCount.Text += "  ⚠️ Exceeds 40-char USR hardware limit!";
        }

        private void TxtDeviceName_TextChanged(object? sender, EventArgs e)
        {
            if (txtDeviceName == null || lblDeviceNameCount == null) return;
            int len = txtDeviceName.Text.Length;
            lblDeviceNameCount.Text      = $"{len} / {PEAK_NAME_MAX}";
            lblDeviceNameCount.ForeColor = len > PEAK_NAME_MAX ? Color.Crimson : Color.DimGray;
        }

        private void CboChannelName_TextChanged(object? sender, EventArgs e)
        {
            if (cboChannelName == null || lblChannelNameCount == null) return;
            int len = cboChannelName.Text.Length;
            lblChannelNameCount.Text      = $"{len} / {PEAK_NOTES_MAX}";
            lblChannelNameCount.ForeColor = len > PEAK_NOTES_MAX ? Color.Crimson : Color.DimGray;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  MOCK SERVER WIRING
        // ══════════════════════════════════════════════════════════════════════
        private void ChkEnableMock_CheckedChanged(object? sender, EventArgs e)
        {
            if (chkEnableMock.Checked)
            {
                if (!int.TryParse(txtMockPort.Text, out int port) || port < 1 || port > 65535)
                {
                    MessageBox.Show("Please enter a valid port number (1–65535).", "Invalid Port",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    chkEnableMock.Checked = false;
                    return;
                }
                string ip = chkMatchSourceIp.Checked
                    ? txtSourceIp.Text.Trim()
                    : txtCustomListenerIp.Text.Trim();
                if (string.IsNullOrEmpty(ip)) ip = "127.0.0.1";
                _mockServer.Start(port, ip, GetCurrentConfig);
                chkRespondToReq.Enabled = true;
            }
            else
            {
                _mockServer.Stop();
                chkRespondToReq.Enabled = false;
                chkRespondToReq.Checked = true;
            }
        }

        private MockServerConfig GetCurrentConfig() => new MockServerConfig(
            Port:              int.TryParse(txtMockPort.Text, out int p)                 ? p   : 35250,
            ProductName:       cboProductName.SelectedItem?.ToString()                   ?? "PCAN-Gateway DR",
            OrderNo:           cboOrderNo.SelectedItem?.ToString()                       ?? "IPEH-004010",
            DeviceName:        txtDeviceName.Text,
            CanCount:          int.TryParse(cboCanCount.SelectedItem?.ToString(), out int cc) ? cc : 2,
            ChannelName:       cboChannelName.Text,
            Bitrate:           int.TryParse(cboBitrate.SelectedItem?.ToString(), out int br)  ? br : 250000,
            Active:            int.TryParse(cboActive.SelectedItem?.ToString(), out int act)  ? act : 1,
            ListenOnly:        int.TryParse(cboListenOnly.SelectedItem?.ToString(), out int lo)? lo : 0,
            RespondToRequests: chkRespondToReq.Checked);

        private void SetMockStatus(string msg)
        {
            if (this.InvokeRequired) { this.Invoke(() => SetMockStatus(msg)); return; }
            lblServerStatus.Text      = msg;
            lblServerStatus.ForeColor = msg.StartsWith("Listening") ? Color.DarkGreen
                                      : msg.StartsWith("Error")     ? Color.Crimson
                                      : Color.DimGray;
        }

        private void AppendRequestLog(string line)
        {
            if (this.InvokeRequired) { this.Invoke(() => AppendRequestLog(line)); return; }
            if (lstRequestLog.Items.Count >= 200) lstRequestLog.Items.RemoveAt(0);
            lstRequestLog.Items.Add(line);
            lstRequestLog.TopIndex = lstRequestLog.Items.Count - 1;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  REPLAY CONTROLS
        // ══════════════════════════════════════════════════════════════════════
        private async void BtnStart_Click(object? sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtPcapPath.Text))
            {
                MessageBox.Show("Please select a PCAP file."); return;
            }

            // Warn if USR override is active and string exceeds hardware limit
            if (chkUsrOverride.Checked && txtUsrMetadata.Text.Length > USR_META_MAX)
            {
                var ans = MessageBox.Show(
                    $"The USR metadata string is {txtUsrMetadata.Text.Length} characters — " +
                    $"exceeds the USR-CANET200 hardware limit of {USR_META_MAX}.\n\n" +
                    "Real hardware would truncate it. Continue anyway for testing purposes?",
                    "Character Limit Exceeded",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (ans == DialogResult.No) return;
            }

            EnableReplayControls(false);
            txtLog.Clear();
            Log("Starting...");

            // Build transformer: one UsrMetadataTransformer per run with the current
            // override string. NullTransformer.Instance used when override is off —
            // no allocation, no USR classification in the hot path.
            IPayloadTransformer transformer = (chkUsrOverride.Checked && !string.IsNullOrWhiteSpace(txtUsrMetadata.Text))
                ? new UsrMetadataTransformer(txtUsrMetadata.Text)
                : NullTransformer.Instance;

            string ip    = txtTargetIp.Text;
            string srcIp = txtSourceIp.Text;
            int    port  = int.TryParse(txtTargetPort.Text, out int p) ? p : -1;
            double speed = double.TryParse(txtSpeed.Text,   out double s) ? s : 1.0;

            var config = new ReplayConfig(
                PcapFile:     txtPcapPath.Text,
                TargetIp:     ip,
                SourceIp:     srcIp,
                PortOverride: port,
                Speed:        speed,
                Loop:         chkLoop.Checked,
                Transformer:  transformer);

            await _engine.RunAsync(config);
        }

        private void EnableReplayControls(bool enable)
        {
            if (this.InvokeRequired) { this.Invoke(() => EnableReplayControls(enable)); return; }
            btnStart.Enabled      = enable;
            txtPcapPath.Enabled   = enable;
            txtSourceIp.Enabled   = enable;
            chkLoop.Enabled       = enable;
            btnStop.Enabled       = !enable;
        }

        private void Log(string msg)
        {
            if (this.InvokeRequired) { this.Invoke(new Action<string>(Log), msg); return; }
            string line = $"[{DateTime.Now:HH:mm:ss}] {msg}\n";
            txtLog.SelectionStart  = txtLog.TextLength;
            txtLog.SelectionLength = 0;
            // Colour key lines for readability
            txtLog.SelectionColor = msg.StartsWith("✅") ? Color.LightGreen
                                  : msg.StartsWith("⚠️") ? Color.Orange
                                  : msg.StartsWith("❓") ? Color.Yellow
                                  : msg.StartsWith("📂") ? Color.DeepSkyBlue
                                  : msg.StartsWith("🔍") ? Color.DeepSkyBlue
                                  : msg.StartsWith("   ") ? Color.Silver
                                  : Color.LightGray;
            txtLog.AppendText(line);
            txtLog.ScrollToCaret();
        }

        // ══════════════════════════════════════════════════════════════════════
        //  LAYOUT HELPERS (inner = relative to a GroupBox)
        // ══════════════════════════════════════════════════════════════════════
        private static void AddSectionHeader(GroupBox grp, int x, int y, string title)
        {
            grp.Controls.Add(new Label
            {
                Text      = title,
                Location  = new Point(x, y),
                AutoSize  = true,
                ForeColor = Color.SteelBlue,
                Font      = new Font("Segoe UI", 8.5f, FontStyle.Bold)
            });
            grp.Controls.Add(new Panel
            {
                Location  = new Point(x, y + 17),
                Size      = new Size(624, 1),
                BackColor = Color.SteelBlue
            });
        }

        private static void AddInner(GroupBox grp, string label, int x, int y,
            out TextBox box, string defaultVal, int w = 120)
        {
            grp.Controls.Add(new Label
            {
                Text     = label,
                Location = new Point(x, y + 3),
                AutoSize = true,
                Font     = new Font("Segoe UI", 9f, FontStyle.Regular)
            });
            box = new TextBox { Text = defaultVal, Location = new Point(x, y + 20), Width = w };
            grp.Controls.Add(box);
        }

        private static void AddComboInner(GroupBox grp, string label, int x, int y,
            out ComboBox combo, string[] items, int selectedIndex, int w = 150)
        {
            grp.Controls.Add(new Label
            {
                Text     = label,
                Location = new Point(x, y + 3),
                AutoSize = true,
                Font     = new Font("Segoe UI", 9f, FontStyle.Regular)
            });
            combo = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Location      = new Point(x, y + 20),
                Width         = w
            };
            combo.Items.AddRange(items);
            combo.SelectedIndex = selectedIndex;
            grp.Controls.Add(combo);
        }

        // ══════════════════════════════════════════════════════════════════════
        //  TRC → USR PCAP TAB
        // ══════════════════════════════════════════════════════════════════════
        private TabPage BuildTrcTab()
        {
            var tab = new TabPage("🔄  TRC → USR PCAP") { Padding = new Padding(10) };
            int y   = 10;

            // ── USR-compatibility banner ──────────────────────────────────────
            var banner = new Panel
            {
                Location  = new Point(10, y),
                Size      = new Size(634, 46),
                BackColor = Color.FromArgb(80, 50, 0)
            };
            banner.Controls.Add(new Label
            {
                Text      = "⚠️  Output is USR-CANET200 compatible — replay with the Replay tab.\n" +
                            "    Source IP below must match the Source IP field on the Replay tab.",
                Location  = new Point(8, 5),
                Size      = new Size(618, 36),
                ForeColor = Color.FromArgb(255, 200, 80),
                Font      = new Font("Segoe UI", 8.5f, FontStyle.Bold)
            });
            tab.Controls.Add(banner);
            y += 56;

            // ── TRC file row ──────────────────────────────────────────────────
            tab.Controls.Add(MakeLabel("TRC File:", 10, y));
            txtTrcPath = new TextBox { Location = new Point(10, y + 20), Width = 500, ReadOnly = true };
            var btnTrcBrowse = new Button { Text = "...", Location = new Point(516, y + 19), Width = 40 };
            btnTrcBrowse.Click += BtnTrcBrowse_Click;
            tab.Controls.AddRange(new Control[] { txtTrcPath, btnTrcBrowse });
            y += 48;

            // ── Output dir row ────────────────────────────────────────────────
            tab.Controls.Add(MakeLabel("Output Directory:", 10, y));
            txtTrcOutputDir = new TextBox { Text = @"C:\logs", Location = new Point(10, y + 20), Width = 400 };
            var btnTrcOutBrowse = new Button { Text = "...", Location = new Point(416, y + 19), Width = 40 };
            btnTrcOutBrowse.Click += BtnTrcOutBrowse_Click;
            txtTrcOutputDir.TextChanged += (s, e) => UpdateTrcOutputLabel();
            tab.Controls.AddRange(new Control[] { txtTrcOutputDir, btnTrcOutBrowse });

            lblTrcOutputName = new Label
            {
                Text      = "Output: (select a .trc file)",
                Location  = new Point(10, y + 44),
                Size      = new Size(620, 18),
                Font      = new Font("Segoe UI", 8f, FontStyle.Italic),
                ForeColor = Color.DimGray
            };
            tab.Controls.Add(lblTrcOutputName);
            y += 70;

            // ── Metadata group ────────────────────────────────────────────────
            var grpMeta = new GroupBox
            {
                Text      = "🏷️  USR-CANET200 Metadata  (first packet header)",
                Location  = new Point(10, y),
                Size      = new Size(634, 118),
                Font      = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.SteelBlue
            };

            int mx = 10, mRow = 22;
            grpMeta.Controls.Add(MakeLabelInner("Asset ID:",   mx,       mRow));
            grpMeta.Controls.Add(MakeLabelInner("Equip Type:", mx + 130, mRow));
            grpMeta.Controls.Add(MakeLabelInner("Mfg:",        mx + 240, mRow));
            grpMeta.Controls.Add(MakeLabelInner("Database:",   mx + 310, mRow));
            grpMeta.Controls.Add(MakeLabelInner("CAN Name:",   mx + 440, mRow));

            txtTrcAssetId   = MakeMetaBox(grpMeta, mx,       mRow + 16, 110, "BLENDER31");
            txtTrcEquipType = MakeMetaBox(grpMeta, mx + 130, mRow + 16, 100, "Blender");
            txtTrcMfg       = MakeMetaBox(grpMeta, mx + 240, mRow + 16, 60,  "CSP");
            txtTrcDatabase  = MakeMetaBox(grpMeta, mx + 310, mRow + 16, 120, "NB,J");
            txtTrcCanName   = MakeMetaBox(grpMeta, mx + 440, mRow + 16, 110, "CAN_ONE");

            EventHandler metaChanged = (s, e) => UpdateTrcAssembled();
            txtTrcAssetId.TextChanged   += metaChanged;
            txtTrcEquipType.TextChanged += metaChanged;
            txtTrcMfg.TextChanged       += metaChanged;
            txtTrcDatabase.TextChanged  += metaChanged;
            txtTrcCanName.TextChanged   += metaChanged;

            lblTrcAssembled = new Label
            {
                Text      = "",
                Location  = new Point(10, mRow + 40),
                Size      = new Size(612, 18),
                Font      = new Font("Consolas", 8f),
                ForeColor = Color.DarkCyan
            };
            grpMeta.Controls.Add(lblTrcAssembled);
            tab.Controls.Add(grpMeta);
            y += 128;

            // ── Network group ─────────────────────────────────────────────────
            var grpNet = new GroupBox
            {
                Text      = "🌐  Network Parameters",
                Location  = new Point(10, y),
                Size      = new Size(634, 72),
                Font      = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.SteelBlue
            };

            int nx = 10;
            AddSimpleField(grpNet, "Source IP:",   nx,       out txtTrcSourceIP,  "192.168.1.100", 110);
            AddSimpleField(grpNet, "Dest IP:",     nx + 130, out txtTrcDestIP,     "192.168.1.1",   110);
            AddSimpleField(grpNet, "Dest Port:",   nx + 260, out txtTrcDestPort,   "35251",          60);
            AddSimpleField(grpNet, "Frames/Pkt:",  nx + 340, out txtTrcFramesPkt,  "10",             50);
            AddSimpleField(grpNet, "Batch (ms):",  nx + 410, out txtTrcBatchMs,    "5",              50);
            tab.Controls.Add(grpNet);
            y += 82;

            // ── Convert button ────────────────────────────────────────────────
            btnTrcConvert = new Button
            {
                Text      = "▶  Convert to USR PCAP",
                Location  = new Point(10, y),
                Width     = 180, Height = 32,
                BackColor = Color.FromArgb(60, 160, 220),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font      = new Font("Segoe UI", 9.5f, FontStyle.Bold)
            };
            btnTrcConvert.FlatAppearance.BorderColor = Color.FromArgb(40, 120, 180);
            btnTrcConvert.Click += BtnTrcConvert_Click;

            btnTrcLoadReplay = new Button
            {
                Text      = "📡  Load in Replay Tab",
                Location  = new Point(200, y),
                Width     = 160, Height = 32,
                BackColor = Color.FromArgb(144, 238, 144),
                FlatStyle = FlatStyle.Flat,
                Enabled   = false,
                Font      = new Font("Segoe UI", 9f, FontStyle.Regular)
            };
            btnTrcLoadReplay.Click += BtnTrcLoadReplay_Click;

            tab.Controls.AddRange(new Control[] { btnTrcConvert, btnTrcLoadReplay });
            y += 42;

            // ── Log panel ─────────────────────────────────────────────────────
            txtTrcLog = new RichTextBox
            {
                Location   = new Point(10, y),
                Width      = 634,
                Height     = 270,
                ReadOnly   = true,
                Font       = new Font("Consolas", 9f),
                BackColor  = Color.FromArgb(20, 20, 20),
                ForeColor  = Color.LightGray,
                ScrollBars = RichTextBoxScrollBars.Vertical
            };
            tab.Controls.Add(txtTrcLog);

            // Trigger initial assembled string
            UpdateTrcAssembled();
            return tab;
        }

        // ── TRC tab helpers ───────────────────────────────────────────────────

        private static Label MakeLabel(string text, int x, int y) =>
            new Label { Text = text, Location = new Point(x, y), AutoSize = true,
                        Font = new Font("Segoe UI", 9f, FontStyle.Regular) };

        private static Label MakeLabelInner(string text, int x, int y) =>
            new Label { Text = text, Location = new Point(x, y), AutoSize = true,
                        Font = new Font("Segoe UI", 8.5f, FontStyle.Regular),
                        ForeColor = Color.Silver };

        private static TextBox MakeMetaBox(GroupBox grp, int x, int y, int w, string def)
        {
            var tb = new TextBox { Text = def, Location = new Point(x, y), Width = w,
                                   Font = new Font("Consolas", 8.5f) };
            grp.Controls.Add(tb);
            return tb;
        }

        private static void AddSimpleField(GroupBox grp, string label, int x,
            out TextBox box, string def, int w)
        {
            grp.Controls.Add(new Label
            {
                Text     = label,
                Location = new Point(x, 20),
                AutoSize = true,
                Font     = new Font("Segoe UI", 8.5f)
            });
            box = new TextBox { Text = def, Location = new Point(x, 38), Width = w };
            grp.Controls.Add(box);
        }

        private void UpdateTrcAssembled()
        {
            if (lblTrcAssembled == null) return;
            string assembled = $"{txtTrcAssetId?.Text}|{txtTrcEquipType?.Text}|" +
                               $"{txtTrcMfg?.Text}|{txtTrcDatabase?.Text}|{txtTrcCanName?.Text}";
            lblTrcAssembled.Text = $"→ {assembled}";
        }

        private void UpdateTrcOutputLabel()
        {
            if (lblTrcOutputName == null) return;
            if (string.IsNullOrWhiteSpace(txtTrcPath?.Text))
            {
                lblTrcOutputName.Text      = "Output: (select a .trc file)";
                lblTrcOutputName.ForeColor = Color.DimGray;
                return;
            }
            string outPath = BuildTrcOutputPath();
            lblTrcOutputName.Text      = $"→ Output: {outPath}";
            lblTrcOutputName.ForeColor = Color.DarkCyan;
        }

        private string BuildTrcOutputPath()
        {
            string baseName  = Path.GetFileNameWithoutExtension(txtTrcPath.Text ?? "");
            string safeBase  = baseName.Replace(' ', '_');
            string dir       = txtTrcOutputDir?.Text?.Trim() ?? @"C:\logs";
            return Path.Combine(dir, $"{safeBase}_usr.pcap");
        }

        private void BtnTrcBrowse_Click(object? sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog
            {
                Title  = "Select PCAN-View TRC file",
                Filter = "TRC Files|*.trc|All Files|*.*"
            };
            if (ofd.ShowDialog() != DialogResult.OK) return;
            txtTrcPath.Text = ofd.FileName;
            UpdateTrcOutputLabel();
            TrcLog($"📂 Loaded: {Path.GetFileName(ofd.FileName)}");
        }

        private void BtnTrcOutBrowse_Click(object? sender, EventArgs e)
        {
            using var fbd = new FolderBrowserDialog
            {
                Description          = "Select output directory for the .pcap file",
                UseDescriptionForTitle = true,
                SelectedPath         = txtTrcOutputDir.Text
            };
            if (fbd.ShowDialog() != DialogResult.OK) return;
            txtTrcOutputDir.Text = fbd.SelectedPath;
        }

        private async void BtnTrcConvert_Click(object? sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtTrcPath.Text))
            {
                MessageBox.Show("Please select a .trc file first.", "No input file",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Build metadata string
            string meta = $"{txtTrcAssetId.Text}|{txtTrcEquipType.Text}|" +
                          $"{txtTrcMfg.Text}|{txtTrcDatabase.Text}|{txtTrcCanName.Text}";

            if (!int.TryParse(txtTrcDestPort.Text,  out int destPort))   destPort   = 35251;
            if (!int.TryParse(txtTrcFramesPkt.Text, out int framesPkt))  framesPkt  = 10;
            if (!double.TryParse(txtTrcBatchMs.Text, out double batchMs)) batchMs   = 5.0;

            var opts = new TrcConversionOptions
            {
                TrcFile         = txtTrcPath.Text,
                OutputPcap      = BuildTrcOutputPath(),
                MetadataHeader  = meta,
                DestPort        = destPort,
                SourceIP        = txtTrcSourceIP.Text.Trim(),
                DestIP          = txtTrcDestIP.Text.Trim(),
                FramesPerPacket = framesPkt,
                BatchThresholdMs = batchMs
            };

            txtTrcLog.Clear();
            btnTrcConvert.Enabled    = false;
            btnTrcLoadReplay.Enabled = false;
            _lastConvertedPcap       = null;

            var progress = new Progress<string>(msg => TrcLog(msg));

            try
            {
                var result = await Task.Run(() => TrcConverter.Convert(opts, progress));

                TrcLog($"✅ Done — {result.FramesParsed} frames → {result.PacketsWritten} packets");
                if (result.Warnings.Count > 0)
                    TrcLog($"⚠️  {result.Warnings.Count} lines skipped (see below)");
                foreach (var w in result.Warnings)
                    TrcLog($"   {w}");

                _lastConvertedPcap       = opts.OutputPcap;
                btnTrcLoadReplay.Enabled = true;
            }
            catch (Exception ex)
            {
                TrcLog($"❌ Error: {ex.Message}");
            }
            finally
            {
                btnTrcConvert.Enabled = true;
            }
        }

        private void BtnTrcLoadReplay_Click(object? sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(_lastConvertedPcap) || !File.Exists(_lastConvertedPcap))
            {
                MessageBox.Show("Converted file not found. Please convert first.",
                    "File Not Found", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            // Pre-populate Replay tab and switch to it
            txtPcapPath.Text    = _lastConvertedPcap;
            txtSourceIp.Text    = txtTrcSourceIP.Text.Trim();

            _tabs.SelectedIndex = 0;  // Switch to Replay tab

            // Trigger analysis so the detection banner updates
            _ = Task.Run(async () =>
            {
                _lastAnalysis = await PcapAnalyzer.AnalyseAsync(_lastConvertedPcap);
                this.Invoke(() =>
                {
                    Log($"📂 Loaded from TRC converter: {Path.GetFileName(_lastConvertedPcap)}");
                    ApplyDetectionResult(_lastAnalysis);
                });
            });
        }

        private void TrcLog(string msg)
        {
            if (this.InvokeRequired) { this.Invoke(new Action<string>(TrcLog), msg); return; }
            string line = $"[{DateTime.Now:HH:mm:ss}] {msg}\n";
            txtTrcLog.SelectionStart  = txtTrcLog.TextLength;
            txtTrcLog.SelectionLength = 0;
            txtTrcLog.SelectionColor  =
                msg.StartsWith("✅") ? Color.LightGreen  :
                msg.StartsWith("⚠️") ? Color.Orange       :
                msg.StartsWith("❌") ? Color.Salmon       :
                msg.StartsWith("📂") ? Color.DeepSkyBlue  :
                msg.StartsWith("💡") ? Color.Gold         :
                msg.StartsWith("   ") ? Color.Silver      :
                Color.LightGray;
            txtTrcLog.AppendText(line);
            txtTrcLog.ScrollToCaret();
        }
    }
}
