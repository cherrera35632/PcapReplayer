using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PcapReplayer
{
    public partial class MainForm
    {
        private TextBox txtCanDbcPath      = null!;
        private TextBox txtCanTargetIp     = null!;
        private TextBox txtCanTargetPort   = null!;
        private TextBox txtCanSourceIp     = null!;
        private TextBox txtCanUsrHeader    = null!;
        private Label lblCanUsrCharCount   = null!;
        private TreeView tvCanMessages     = null!;
        private CheckBox chkCanMsgEnabled  = null!;
        private NumericUpDown nudCanMsgRate = null!;
        private Label lblCanMsgInfo        = null!;
        private FlowLayoutPanel flpCanSignals = null!;
        private Button btnCanStart         = null!;
        private Button btnCanStop          = null!;
        private Label lblCanSentCount      = null!;
        private RichTextBox txtCanGenLog   = null!;
        private Panel pnlCanConfig         = null!;
        private GroupBox grpCanMessages    = null!;
        private Panel pnlCanDetailHeader   = null!;
        private ToolTip _canToolTip        = new();

        // SA override controls (only visible for J1939 extended messages)
        private CheckBox chkOverrideSa     = null!;
        private NumericUpDown nudOverrideSa = null!;
        private Label lblOverrideSaHex     = null!;

        // Favorites quick-access bar
        private ComboBox cboFavorites      = null!;
        private CheckBox chkMarkFavorite   = null!;
        private Label    lblFavoritesHint  = null!;

        // Live search bar
        private TextBox txtCanSearch       = null!;
        private Label   lblCanSearchStatus = null!;

        private ICanTransmitter _canTx = null!;
        private DbcDatabase? _canDatabase;
        private List<MessageTxState> _canMessages = new();
        private MessageTxState? _selectedCanMessage;
        private CancellationTokenSource? _canTxCts;

        private TabPage BuildCanGenTab()
        {
            var tab = new TabPage("🛠 CAN Generator") { Padding = new Padding(10) };

            pnlCanConfig = new Panel
            {
                Location = new Point(10, 10),
                Size     = new Size(634, 108)
            };

            pnlCanConfig.Controls.Add(new Label { Text = "DBC File:", Location = new Point(0, 6), AutoSize = true });
            txtCanDbcPath = new TextBox { Location = new Point(0, 26), Width = 520, ReadOnly = true };
            var btnCanBrowse = new Button { Text = "...", Location = new Point(526, 25), Width = 40 };
            btnCanBrowse.Click += BtnCanBrowse_Click;
            pnlCanConfig.Controls.AddRange(new Control[] { txtCanDbcPath, btnCanBrowse });

            pnlCanConfig.Controls.Add(new Label { Text = "Target IP:", Location = new Point(0, 56), AutoSize = true });
            txtCanTargetIp = new TextBox { Text = "127.0.0.1", Location = new Point(0, 76), Width = 110 };
            pnlCanConfig.Controls.Add(txtCanTargetIp);

            pnlCanConfig.Controls.Add(new Label { Text = "Port:", Location = new Point(120, 56), AutoSize = true });
            txtCanTargetPort = new TextBox { Text = "35281", Location = new Point(120, 76), Width = 70 };
            pnlCanConfig.Controls.Add(txtCanTargetPort);

            pnlCanConfig.Controls.Add(new Label { Text = "Source IP:", Location = new Point(200, 56), AutoSize = true });
            txtCanSourceIp = new TextBox { Text = "127.0.0.2", Location = new Point(200, 76), Width = 120 };
            pnlCanConfig.Controls.Add(txtCanSourceIp);

            pnlCanConfig.Controls.Add(new Label { Text = "USR Header:", Location = new Point(330, 56), AutoSize = true });
            txtCanUsrHeader = new TextBox
            {
                Text     = "123456|P|R|dbcName|C1|1",
                Location = new Point(330, 76),
                Width    = 230,
                Font     = new Font("Consolas", 8.5f)
            };
            txtCanUsrHeader.TextChanged += (s, e) =>
            {
                UpdateCanUsrHeaderCount();
                UpdateCanStartState();
            };
            pnlCanConfig.Controls.Add(txtCanUsrHeader);

            lblCanUsrCharCount = new Label
            {
                Text      = $"0 / {USR_META_MAX}",
                Location  = new Point(565, 79),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 8.5f),
                ForeColor = Color.DimGray
            };
            pnlCanConfig.Controls.Add(lblCanUsrCharCount);

            txtCanTargetIp.TextChanged   += (s, e) => UpdateCanStartState();
            txtCanTargetPort.TextChanged += (s, e) => UpdateCanStartState();
            txtCanSourceIp.TextChanged   += (s, e) => UpdateCanStartState();

            // ── Favorites bar ────────────────────────────────────────────────────────────
            var pnlFavorites = new Panel
            {
                Location  = new Point(10, 122),
                Size      = new Size(634, 28),
                BackColor = Color.FromArgb(255, 253, 235)   // warm cream tint
            };

            pnlFavorites.Controls.Add(new Label
            {
                Text      = "⭐ Favorites:",
                Location  = new Point(2, 6),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.DarkGoldenrod
            });

            cboFavorites = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Location      = new Point(84, 3),
                Width         = 430,
                Font          = new Font("Segoe UI", 8.5f),
                Enabled       = false
            };
            cboFavorites.SelectedIndexChanged += CboFavorites_SelectedIndexChanged;
            pnlFavorites.Controls.Add(cboFavorites);

            lblFavoritesHint = new Label
            {
                Text      = "(no favorites yet — check ⭐ on a message)",
                Location  = new Point(84, 7),
                Width     = 430,
                AutoSize  = false,
                Font      = new Font("Segoe UI", 8f, FontStyle.Italic),
                ForeColor = Color.DarkGoldenrod
            };
            pnlFavorites.Controls.Add(lblFavoritesHint);

            // ── Search bar ─────────────────────────────────────────────────────────
            var pnlSearch = new Panel
            {
                Location  = new Point(10, 150),
                Size      = new Size(634, 28),
                BackColor = Color.FromArgb(235, 244, 255)   // light blue tint
            };

            pnlSearch.Controls.Add(new Label
            {
                Text      = "🔍 Search:",
                Location  = new Point(2, 6),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                ForeColor = Color.SteelBlue
            });

            txtCanSearch = new TextBox
            {
                Location     = new Point(70, 4),
                Width        = 320,
                Font         = new Font("Segoe UI", 8.5f),
                PlaceholderText = "Message name or CAN ID (e.g. ENG_SPEED or 18FD9BFE)"
            };
            txtCanSearch.TextChanged += CanSearch_TextChanged;
            pnlSearch.Controls.Add(txtCanSearch);

            lblCanSearchStatus = new Label
            {
                Location  = new Point(396, 7),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 8f, FontStyle.Italic),
                ForeColor = Color.SteelBlue
            };
            pnlSearch.Controls.Add(lblCanSearchStatus);

            // ── Messages group box ───────────────────────────────────────────────────────
            grpCanMessages = new GroupBox
            {
                Text      = "Messages (PGN → Message → Signal)",
                Location  = new Point(10, 184),
                Size      = new Size(634, 290),
                Font      = new Font("Segoe UI", 9f, FontStyle.Bold),
                ForeColor = Color.SteelBlue
            };

            var split = new SplitContainer
            {
                Dock          = DockStyle.Fill,
                Width         = 634,   // must be set before MinSize properties; avoids Width−Panel2MinSize going negative
                Panel1MinSize = 180,
                Panel2MinSize = 200
            };

            tvCanMessages = new TreeView
            {
                Dock      = DockStyle.Fill,
                Font      = new Font("Segoe UI", 8.75f),
                HideSelection = false
            };
            tvCanMessages.AfterSelect += TvCanMessages_AfterSelect;
            split.Panel1.Controls.Add(tvCanMessages);

            var detailPanel = new Panel { Dock = DockStyle.Fill };
            pnlCanDetailHeader = new Panel { Dock = DockStyle.Top, Height = 84 };
            lblCanMsgInfo = new Label
            {
                Text      = "Select a CAN message from the tree.",
                Location  = new Point(8, 8),
                Size      = new Size(360, 18),
                ForeColor = Color.DimGray,
                Font      = new Font("Segoe UI", 8.5f, FontStyle.Italic)
            };
            chkCanMsgEnabled = new CheckBox
            {
                Text     = "Enable message",
                Location = new Point(8, 32),
                AutoSize = true,
                Enabled  = false,
                Font     = new Font("Segoe UI", 8.5f)
            };
            chkCanMsgEnabled.CheckedChanged += (s, e) =>
            {
                if (_selectedCanMessage == null) return;
                // If a mux group is selected, toggle that group; otherwise toggle the whole message
                if (chkCanMsgEnabled.Tag is MultiplexGroup group)
                    group.Enabled = chkCanMsgEnabled.Checked;
                else
                    _selectedCanMessage.Enabled = chkCanMsgEnabled.Checked;
                UpdateCanStartState();
                RefreshTreeLabels();
            };

            pnlCanDetailHeader.Controls.Add(lblCanMsgInfo);
            pnlCanDetailHeader.Controls.Add(chkCanMsgEnabled);
            pnlCanDetailHeader.Controls.Add(new Label { Text = "Rate (ms):", Location = new Point(150, 33), AutoSize = true, Font = new Font("Segoe UI", 8.5f) });
            nudCanMsgRate = new NumericUpDown
            {
                Location     = new Point(215, 30),
                Width        = 70,
                Minimum      = 1,
                Maximum      = 60000,
                Enabled      = false,
                ThousandsSeparator = true
            };
            nudCanMsgRate.ValueChanged += (s, e) =>
            {
                if (_selectedCanMessage == null) return;
                // If a mux group is selected (via Tag), set its individual period
                if (nudCanMsgRate.Tag is MultiplexGroup muxGroup)
                    muxGroup.PeriodMs = (int)nudCanMsgRate.Value;
                else
                    _selectedCanMessage.PeriodMs = (int)nudCanMsgRate.Value;
            };
            pnlCanDetailHeader.Controls.Add(nudCanMsgRate);

            // ⭐ Mark favorite — row 3
            chkMarkFavorite = new CheckBox
            {
                Text      = "⭐ Favorite",
                Location  = new Point(8, 61),
                AutoSize  = true,
                Enabled   = false,
                Font      = new Font("Segoe UI", 8.5f),
                ForeColor = Color.DarkGoldenrod
            };
            chkMarkFavorite.CheckedChanged += ChkMarkFavorite_Changed;
            pnlCanDetailHeader.Controls.Add(chkMarkFavorite);

            // SA override — row 3, shown only for J1939 extended messages
            chkOverrideSa = new CheckBox
            {
                Text      = "Override SA:",
                Location  = new Point(110, 61),
                AutoSize  = true,
                Enabled   = false,
                Visible   = false,
                Font      = new Font("Segoe UI", 8.5f)
            };
            nudOverrideSa = new NumericUpDown
            {
                Location  = new Point(210, 58),
                Width     = 60,
                Minimum   = 0,
                Maximum   = 255,
                Enabled   = false,
                Visible   = false,
                Font      = new Font("Segoe UI", 8.5f)
            };
            lblOverrideSaHex = new Label
            {
                Location  = new Point(275, 62),
                Width     = 46,
                AutoSize  = false,
                Font      = new Font("Consolas", 8f),
                ForeColor = Color.DimGray,
                Visible   = false
            };

            chkOverrideSa.CheckedChanged += (s, e) =>
            {
                nudOverrideSa.Enabled = chkOverrideSa.Checked;
                if (_selectedCanMessage == null) return;
                _selectedCanMessage.OverrideSa = chkOverrideSa.Checked
                    ? (byte)nudOverrideSa.Value
                    : (byte?)null;
                UpdateSaHexLabel();
            };
            nudOverrideSa.ValueChanged += (s, e) =>
            {
                if (_selectedCanMessage == null) return;
                if (chkOverrideSa.Checked)
                    _selectedCanMessage.OverrideSa = (byte)nudOverrideSa.Value;
                UpdateSaHexLabel();
            };

            pnlCanDetailHeader.Controls.Add(chkOverrideSa);
            pnlCanDetailHeader.Controls.Add(nudOverrideSa);
            pnlCanDetailHeader.Controls.Add(lblOverrideSaHex);

            flpCanSignals = new FlowLayoutPanel
            {
                Dock          = DockStyle.Fill,
                AutoScroll    = true,
                FlowDirection = FlowDirection.TopDown,
                WrapContents  = false,
                Padding       = new Padding(6)
            };

            detailPanel.Controls.Add(flpCanSignals);
            detailPanel.Controls.Add(pnlCanDetailHeader);
            split.Panel2.Controls.Add(detailPanel);
            grpCanMessages.Controls.Add(split);

            btnCanStart = new Button
            {
                Text      = "▶ Start TX",
                Location  = new Point(10, 484),
                Width     = 120,
                BackColor = Color.FromArgb(144, 238, 144),
                FlatStyle = FlatStyle.Flat,
                Enabled   = false
            };
            btnCanStart.Click += BtnCanStart_Click;

            btnCanStop = new Button
            {
                Text      = "■ Stop",
                Location  = new Point(140, 484),
                Width     = 90,
                BackColor = Color.FromArgb(255, 160, 122),
                FlatStyle = FlatStyle.Flat,
                Enabled   = false
            };
            btnCanStop.Click += BtnCanStop_Click;

            lblCanSentCount = new Label
            {
                Text      = "Sent: 0 frames",
                Location  = new Point(250, 490),
                AutoSize  = true,
                Font      = new Font("Consolas", 9f),
                ForeColor = Color.DimGray
            };

            txtCanGenLog = new RichTextBox
            {
                Location   = new Point(10, 520),
                Width      = 634,
                Height     = 195,
                ReadOnly   = true,
                Font       = new Font("Consolas", 9f),
                BackColor  = Color.FromArgb(20, 20, 20),
                ForeColor  = Color.LightGray,
                ScrollBars = RichTextBoxScrollBars.Vertical
            };

            // Shift Start/Stop/Log controls down to account for the favorites bar
            btnCanStart.Location    = new Point(10, 484);
            btnCanStop.Location     = new Point(140, 484);
            lblCanSentCount.Location= new Point(250, 490);
            txtCanGenLog.Location   = new Point(10, 520);

            tab.Controls.AddRange(new Control[]
            {
                pnlCanConfig,
                pnlFavorites,
                pnlSearch,
                grpCanMessages,
                btnCanStart,
                btnCanStop,
                lblCanSentCount,
                txtCanGenLog
            });

            UpdateCanUsrHeaderCount();
            return tab;
        }

        private void BtnCanBrowse_Click(object? sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog { Filter = "DBC Files|*.dbc|All Files|*.*" };
            if (ofd.ShowDialog() != DialogResult.OK) return;

            try
            {
                _canDatabase = DbcParser.ParseFile(ofd.FileName);
                _canMessages = BuildMessageStates(_canDatabase);
                txtCanDbcPath.Text = ofd.FileName;
                txtCanGenLog.Clear();

                // Auto-update the Database field (index 3) in the USR header with the DBC name
                UpdateUsrHeaderDbcName(Path.GetFileNameWithoutExtension(ofd.FileName));

                RebuildCanTree();

                CanGenLog($"DBC loaded: {Path.GetFileName(ofd.FileName)} ({_canDatabase.MessageCount} msgs, {_canDatabase.SignalCount} sigs)");
                foreach (string warning in _canDatabase.Warnings.Take(5))
                    CanGenLog($"⚠️ {warning}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to load DBC:\n{ex.Message}", "DBC Load Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                CanGenLog($"❌ Error: {ex.Message}");
            }

            UpdateCanStartState();
        }

        private void UpdateUsrHeaderDbcName(string dbcName)
        {
            string current = txtCanUsrHeader.Text;
            string[] parts = current.Split('|');
            if (parts.Length >= 4)
            {
                parts[3] = dbcName;
                txtCanUsrHeader.Text = string.Join("|", parts);
            }
        }

        private List<MessageTxState> BuildMessageStates(DbcDatabase database)
        {
            var result = new List<MessageTxState>();
            foreach (var message in database.Messages.OrderBy(m => m.Name, StringComparer.OrdinalIgnoreCase))
            {
                var state = new MessageTxState
                {
                    Name       = message.Name,
                    CanId      = message.CanId,
                    IsExtended = message.IsExtended,
                    Dlc        = (byte)Math.Min(8, (int)message.Dlc),
                    Comment    = message.Comment,
                    PeriodMs   = 1000,
                    Enabled    = false
                };

                // Separate normal, multiplexor, and multiplexed signals
                DbcSignal? muxorSignal = null;
                var muxedSignals = new Dictionary<int, List<DbcSignal>>();
                var normalSignals = new List<DbcSignal>();

                foreach (var signal in message.Signals)
                {
                    if (signal.MultiplexIndicator == "M")
                    {
                        muxorSignal = signal;
                    }
                    else if (signal.MultiplexIndicator != null &&
                             signal.MultiplexIndicator.StartsWith("m", StringComparison.Ordinal) &&
                             int.TryParse(signal.MultiplexIndicator[1..], out int muxIdx))
                    {
                        if (!muxedSignals.TryGetValue(muxIdx, out var list))
                        {
                            list = new List<DbcSignal>();
                            muxedSignals[muxIdx] = list;
                        }
                        list.Add(signal);
                    }
                    else
                    {
                        normalSignals.Add(signal);
                    }
                }

                // Add normal signals to state.Signals
                foreach (var signal in normalSignals)
                    state.Signals.Add(BuildSignalState(signal));

                // If message has multiplex structure, build the groups
                if (muxorSignal != null && muxedSignals.Count > 0)
                {
                    var muxorState = BuildSignalState(muxorSignal);
                    muxorState.IsMuted = false; // multiplexor is always active
                    state.MultiplexorSignal = muxorState;
                    state.Signals.Add(muxorState); // also in Signals list for display

                    var groups = new SortedDictionary<int, MultiplexGroup>();
                    foreach (var (muxValue, signals) in muxedSignals.OrderBy(kv => kv.Key))
                    {
                        var group = new MultiplexGroup { MuxValue = muxValue };
                        foreach (var signal in signals)
                            group.Signals.Add(BuildSignalState(signal));
                        groups[muxValue] = group;
                    }
                    state.MultiplexGroups = groups;
                }
                else
                {
                    // Non-multiplexed: add any remaining signals normally
                    // (muxorSignal without muxed signals is treated as normal)
                    if (muxorSignal != null)
                        state.Signals.Add(BuildSignalState(muxorSignal));
                }

                UsrFrameBuilder.BuildDataBytes(state);
                result.Add(state);
            }

            return result;
        }

        private static SignalTxState BuildSignalState(DbcSignal signal)
        {
            double physical = signal.Min + ((signal.Max - signal.Min) / 2.0);
            bool ok = SignalEncoder.TryEncodePhysical(signal, physical, out long raw, out string? error);

            if (!ok)
            {
                physical = Math.Min(signal.Min, signal.Max);
                ok = SignalEncoder.TryEncodePhysical(signal, physical, out raw, out error);
            }

            if (signal.ValueTable is { Count: > 0 })
            {
                long closestRaw = signal.ValueTable.Keys.OrderBy(v => Math.Abs(v - raw)).First();
                physical = closestRaw * signal.Factor + signal.Offset;
                ok = SignalEncoder.TryEncodePhysical(signal, physical, out raw, out error);
            }

            if (!ok)
            {
                raw = 0;
                physical = signal.Offset;
                error ??= "Unable to derive a valid default value from the DBC signal definition.";
            }

            return new SignalTxState
            {
                Signal        = signal,
                PhysicalValue = physical,
                RawValue      = raw,
                Error         = error,
                IsMuted       = true
            };
        }

        /// <summary>
        /// Refreshes the Favorites combo box to reflect the current <see cref="MessageTxState.IsFavorite"/> flags.
        /// Call this whenever a message's favorite state changes or the tree is rebuilt.
        /// </summary>
        private void RefreshFavoritesBar()
        {
            cboFavorites.SelectedIndexChanged -= CboFavorites_SelectedIndexChanged;
            cboFavorites.Items.Clear();

            foreach (var msg in _canMessages.Where(m => m.IsFavorite))
                cboFavorites.Items.Add(new FavoriteEntry(msg));

            bool hasFavs = cboFavorites.Items.Count > 0;
            cboFavorites.Enabled       = hasFavs;
            cboFavorites.Visible       = hasFavs;
            lblFavoritesHint.Visible   = !hasFavs;

            // Re-select current message in the combo if it is a favorite
            if (_selectedCanMessage != null && _selectedCanMessage.IsFavorite)
            {
                var target = cboFavorites.Items.Cast<FavoriteEntry>()
                    .FirstOrDefault(fe => ReferenceEquals(fe.Message, _selectedCanMessage));
                if (target != null) cboFavorites.SelectedItem = target;
            }

            cboFavorites.SelectedIndexChanged += CboFavorites_SelectedIndexChanged;
            // Also reflect the star checkbox for the currently shown message
            SyncStarCheckbox();
        }

        private void CboFavorites_SelectedIndexChanged(object? sender, EventArgs e)
        {
            if (cboFavorites.SelectedItem is FavoriteEntry entry)
                NavigateToMessage(entry.Message);
        }

        /// <summary>Selects the tree node that corresponds to <paramref name="message"/>.</summary>
        private void NavigateToMessage(MessageTxState message)
        {
            foreach (TreeNode pgn in tvCanMessages.Nodes)
            {
                foreach (TreeNode msgNode in pgn.Nodes)
                {
                    if (ReferenceEquals(msgNode.Tag, message))
                    {
                        tvCanMessages.SelectedNode = msgNode;
                        msgNode.EnsureVisible();
                        return;
                    }
                }
            }
        }

        /// <summary>Syncs the ⭐ checkbox to the currently selected message without re-raising events.</summary>
        private void SyncStarCheckbox()
        {
            chkMarkFavorite.CheckedChanged -= ChkMarkFavorite_Changed;
            bool msgSelected = _selectedCanMessage != null;
            chkMarkFavorite.Enabled = msgSelected;
            chkMarkFavorite.Checked = msgSelected && _selectedCanMessage!.IsFavorite;
            chkMarkFavorite.CheckedChanged += ChkMarkFavorite_Changed;
        }

        private void ChkMarkFavorite_Changed(object? sender, EventArgs e)
        {
            if (_selectedCanMessage == null) return;
            _selectedCanMessage.IsFavorite = chkMarkFavorite.Checked;
            RefreshFavoritesBar();
        }

        // ── Live search ──────────────────────────────────────────────────────────────────

        private void CanSearch_TextChanged(object? sender, EventArgs e)
        {
            string raw = txtCanSearch.Text.Trim();

            if (string.IsNullOrEmpty(raw))
            {
                lblCanSearchStatus.Text      = string.Empty;
                lblCanSearchStatus.ForeColor = Color.SteelBlue;
                return;
            }

            string query   = NormalizeSearchQuery(raw);
            var    matches = SearchCanTree(query);

            if (matches.Count == 0)
            {
                lblCanSearchStatus.Text      = "no match";
                lblCanSearchStatus.ForeColor = Color.Crimson;
                return;
            }

            tvCanMessages.SelectedNode = matches[0];
            matches[0].EnsureVisible();

            lblCanSearchStatus.Text      = matches.Count == 1 ? "1 match" : $"{matches.Count} matches";
            lblCanSearchStatus.ForeColor = Color.SeaGreen;
        }

        /// <summary>
        /// Strips a leading "0x" / "0X" prefix so users can enter hex IDs either way.
        /// The result is the normalised query string passed to <see cref="MessageMatchesSearchQuery"/>.
        /// </summary>
        internal static string NormalizeSearchQuery(string raw)
            => raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? raw[2..] : raw;

        /// <summary>
        /// Returns <see langword="true"/> when <paramref name="msg"/> matches a normalised
        /// (no "0x" prefix) <paramref name="query"/>:
        /// <list type="bullet">
        ///   <item>Message name <em>contains</em> the query (case-insensitive), or</item>
        ///   <item>Hex CAN-ID <em>starts with</em> the query (case-insensitive).</item>
        /// </list>
        /// </summary>
        internal static bool MessageMatchesSearchQuery(MessageTxState msg, string query)
        {
            if (string.IsNullOrEmpty(query)) return false;

            bool nameMatch = msg.Name.Contains(query, StringComparison.OrdinalIgnoreCase);

            string hexId  = msg.IsExtended ? $"{msg.CanId:X8}" : $"{msg.CanId:X3}";
            bool idMatch  = hexId.StartsWith(query, StringComparison.OrdinalIgnoreCase);

            return nameMatch || idMatch;
        }

        /// <summary>
        /// Returns all message-level <see cref="TreeNode"/>s that satisfy
        /// <see cref="MessageMatchesSearchQuery"/> for the given normalised query.
        /// </summary>
        private List<TreeNode> SearchCanTree(string query)
        {
            var results = new List<TreeNode>();
            foreach (TreeNode pgn in tvCanMessages.Nodes)
            {
                foreach (TreeNode msgNode in pgn.Nodes)
                {
                    if (msgNode.Tag is not MessageTxState msg) continue;
                    if (MessageMatchesSearchQuery(msg, query))
                        results.Add(msgNode);
                }
            }
            return results;
        }

        private void RebuildCanTree()
        {
            tvCanMessages.BeginUpdate();
            try
            {
                tvCanMessages.Nodes.Clear();
                _selectedCanMessage = null;
                flpCanSignals.Controls.Clear();
                chkCanMsgEnabled.Enabled  = false;
                nudCanMsgRate.Enabled     = false;
                chkMarkFavorite.Enabled   = false;
                chkMarkFavorite.Checked   = false;
                lblCanMsgInfo.Text       = "Select a CAN message from the tree.";
                lblCanMsgInfo.ForeColor  = Color.DimGray;

                var parentNodes = new Dictionary<string, TreeNode>();
                foreach (var message in _canMessages)
                {
                    string parentKey = J1939IdDecoder.TryDecode(message.CanId, message.IsExtended, out var j1939)
                        ? $"PGN {j1939.Pgn}"
                        : "Standard CAN";

                    if (!parentNodes.TryGetValue(parentKey, out var parentNode))
                    {
                        parentNode = new TreeNode(parentKey);
                        parentNodes[parentKey] = parentNode;
                        tvCanMessages.Nodes.Add(parentNode);
                    }

                    var messageNode = new TreeNode(FormatMessageNodeText(message)) { Tag = message };

                    // Add normal (non-mux) signals
                    foreach (var signal in message.Signals)
                    {
                        if (signal.Signal.MultiplexIndicator == "M") continue; // skip multiplexor in normal list
                        messageNode.Nodes.Add(new TreeNode(FormatSignalText(signal)) { Tag = new SignalNodeTag(message, signal) });
                    }

                    // Add multiplex groups as sub-tree
                    if (message.IsMultiplexed && message.MultiplexGroups != null)
                    {
                        string muxorName = message.MultiplexorSignal?.Signal.Name ?? "Mux";
                        var muxParentNode = new TreeNode($"🔀 {muxorName} (multiplexed)")
                        {
                            ForeColor = Color.MediumSlateBlue,
                            Tag = new MuxParentNodeTag(message)
                        };

                        foreach (var (muxValue, group) in message.MultiplexGroups)
                        {
                            var groupNode = new TreeNode($"m{muxValue}")
                            {
                                Tag = new MuxGroupNodeTag(message, muxValue, group)
                            };
                            foreach (var signal in group.Signals)
                            {
                                groupNode.Nodes.Add(new TreeNode(FormatSignalText(signal))
                                {
                                    Tag = new SignalNodeTag(message, signal)
                                });
                            }
                            muxParentNode.Nodes.Add(groupNode);
                        }

                        messageNode.Nodes.Add(muxParentNode);
                    }

                    parentNode.Nodes.Add(messageNode);
                    parentNode.Expand();
                }

                TreeNode? firstMessage = tvCanMessages.Nodes.Cast<TreeNode>()
                    .SelectMany(n => n.Nodes.Cast<TreeNode>())
                    .FirstOrDefault();
                if (firstMessage != null)
                    tvCanMessages.SelectedNode = firstMessage;
            }
            finally
            {
                tvCanMessages.EndUpdate();
            }

            // Rebuild favorites combo after the tree is ready
            RefreshFavoritesBar();
        }

        private void RefreshTreeLabels()
        {
            tvCanMessages.BeginUpdate();
            try
            {
                foreach (TreeNode parent in tvCanMessages.Nodes)
                {
                    foreach (TreeNode child in parent.Nodes)
                    {
                        if (child.Tag is MessageTxState message)
                        {
                            child.Text = FormatMessageNodeText(message);
                            foreach (TreeNode signalNode in child.Nodes)
                            {
                                if (signalNode.Tag is SignalNodeTag signalTag)
                                    signalNode.Text = FormatSignalText(signalTag.Signal);
                            }
                        }
                    }
                }
            }
            finally
            {
                tvCanMessages.EndUpdate();
            }
        }

        private static string FormatMessageNodeText(MessageTxState message)
        {
            string enabled = message.Enabled ? string.Empty : " [disabled]";
            string idText = message.IsExtended ? $"0x{message.CanId:X8}" : $"0x{message.CanId:X3}";
            return $"{message.Name}  ID={idText}  DLC={message.Dlc}  Rate={message.PeriodMs}ms{enabled}";
        }

        private static string FormatSignalText(SignalTxState signal)
        {
            string spnText = signal.Signal.Spn.HasValue ? $" (SPN {signal.Signal.Spn.Value})" : string.Empty;
            string mutedText = signal.IsMuted ? " [muted]" : string.Empty;
            return $"{signal.Signal.Name}{spnText}{mutedText}";
        }

        private void TvCanMessages_AfterSelect(object? sender, TreeViewEventArgs e)
        {
            if (e.Node?.Tag is MessageTxState message)
            {
                ShowMessageDetails(message);
                return;
            }

            if (e.Node?.Tag is SignalNodeTag signalTag)
            {
                // If this signal lives inside a mux group node, show that group's details
                if (e.Node.Parent?.Tag is MuxGroupNodeTag parentMuxTag)
                {
                    ShowMuxGroupDetails(parentMuxTag.Message, parentMuxTag.MuxValue, parentMuxTag.Group);
                    return;
                }
                ShowMessageDetails(signalTag.Message);
                return;
            }

            if (e.Node?.Tag is MuxGroupNodeTag muxGroupTag)
            {
                ShowMuxGroupDetails(muxGroupTag.Message, muxGroupTag.MuxValue, muxGroupTag.Group);
                return;
            }

            if (e.Node?.Tag is MuxParentNodeTag muxParentTag)
            {
                ShowMuxParentDetails(muxParentTag.Message);
                return;
            }

            ShowMessageDetails(null);
        }

        private void ShowMessageDetails(MessageTxState? message)
        {
            _selectedCanMessage = message;
            flpCanSignals.SuspendLayout();
            flpCanSignals.Controls.Clear();

            if (message == null)
            {
                chkCanMsgEnabled.Enabled = false;
                nudCanMsgRate.Enabled    = false;
                nudCanMsgRate.Tag        = null;
                lblCanMsgInfo.Text       = "Select a CAN message from the tree.";
                lblCanMsgInfo.ForeColor  = Color.DimGray;
                ApplySaOverrideControls(null);
                flpCanSignals.ResumeLayout();
                return;
            }

            chkCanMsgEnabled.Text    = "Enable message";
            chkCanMsgEnabled.Enabled = true;
            chkCanMsgEnabled.Checked = message.Enabled;
            chkCanMsgEnabled.Tag     = null; // not bound to a mux group
            nudCanMsgRate.Tag        = null; // not bound to a mux group
            SyncStarCheckbox();
            if (message.IsMultiplexed)
            {
                // Rate is per-group for muxed messages; show nothing at message level
                nudCanMsgRate.Enabled = false;
                nudCanMsgRate.Value   = nudCanMsgRate.Minimum; // clear stale value
            }
            else
            {
                nudCanMsgRate.Enabled = true;
                nudCanMsgRate.Value   = message.PeriodMs;
            }
            string infoText = $"{message.Name}  ID=0x{message.CanId:X8}  DLC={message.Dlc}";
            if (message.IsMultiplexed && message.MultiplexGroups != null)
            {
                int enabledCount = message.MultiplexGroups.Values.Count(g => g.Enabled);
                infoText += $"  [{enabledCount} mux groups enabled — select a group to set its rate]";
            }
            lblCanMsgInfo.Text       = infoText;
            lblCanMsgInfo.ForeColor  = Color.Black;
            ApplySaOverrideControls(message);

            foreach (var signal in message.Signals)
            {
                // Hide the multiplexor signal — its value is set automatically per mux group
                if (signal.Signal.MultiplexIndicator == "M") continue;
                flpCanSignals.Controls.Add(BuildSignalRow(message, signal));
            }

            flpCanSignals.ResumeLayout();
            UpdateCanStartState();
        }

        /// <summary>
        /// Shown when the user clicks the "🔀 SignalName (multiplexed)" parent node.
        /// Displays a read-only summary of all groups; directs the user to click a group
        /// node (m0, m1, …) to configure its individual rate and signals.
        /// </summary>
        private void ShowMuxParentDetails(MessageTxState message)
        {
            _selectedCanMessage = message;
            flpCanSignals.SuspendLayout();
            flpCanSignals.Controls.Clear();

            // Rate and enable are not meaningful at the mux-parent level
            chkCanMsgEnabled.Text    = "Enable message";
            chkCanMsgEnabled.Enabled = true;
            chkCanMsgEnabled.Checked = message.Enabled;
            chkCanMsgEnabled.Tag     = null;
            nudCanMsgRate.Enabled    = false;
            nudCanMsgRate.Tag        = null;
            nudCanMsgRate.Value      = nudCanMsgRate.Minimum; // clear any stale value
            SyncStarCheckbox();

            int groupCount   = message.MultiplexGroups?.Count ?? 0;
            int enabledCount = message.MultiplexGroups?.Values.Count(g => g.Enabled) ?? 0;
            string muxorName = message.MultiplexorSignal?.Signal.Name ?? "Mux";
            lblCanMsgInfo.Text      = $"{message.Name}  Multiplexor: {muxorName}  "
                                    + $"{groupCount} groups ({enabledCount} enabled) — select m# to set rate";
            lblCanMsgInfo.ForeColor = Color.MediumSlateBlue;
            ApplySaOverrideControls(message);

            // Show a compact summary row for each group
            if (message.MultiplexGroups != null)
            {
                foreach (var (muxValue, group) in message.MultiplexGroups)
                {
                    var summary = new Label
                    {
                        Text      = $"m{muxValue}  — {group.Signals.Count} signals  "
                                  + $"Rate={group.PeriodMs} ms  "
                                  + (group.Enabled ? "[enabled]" : "[disabled]"),
                        AutoSize  = true,
                        Font      = new Font("Consolas", 8.5f),
                        ForeColor = group.Enabled ? Color.DarkSlateBlue : Color.Gray,
                        Margin    = new Padding(4, 4, 0, 0)
                    };
                    flpCanSignals.Controls.Add(summary);
                }
            }

            flpCanSignals.ResumeLayout();
            UpdateCanStartState();
        }

        private void ShowMuxGroupDetails(MessageTxState message, int muxValue, MultiplexGroup group)
        {
            _selectedCanMessage = message;
            flpCanSignals.SuspendLayout();
            flpCanSignals.Controls.Clear();

            // Enable checkbox toggles the individual mux group
            chkCanMsgEnabled.Text    = $"Enable m{muxValue}";
            chkCanMsgEnabled.Enabled = true;
            chkCanMsgEnabled.Checked = group.Enabled;
            chkCanMsgEnabled.Tag     = group; // track which group is bound

            // Rate controls this individual mux group's period
            nudCanMsgRate.Enabled = true;
            nudCanMsgRate.Tag     = group; // track which group is bound for ValueChanged
            nudCanMsgRate.Value   = group.PeriodMs;

            // Star reflects the parent message (groups don't have their own favorite state)
            SyncStarCheckbox();

            int enabledCount = message.MultiplexGroups?.Values.Count(g => g.Enabled) ?? 0;
            lblCanMsgInfo.Text = $"{message.Name}  Mux m{muxValue}  ({group.Signals.Count} signals)  " +
                                 $"Rate={group.PeriodMs}ms  [{enabledCount} groups enabled]";
            lblCanMsgInfo.ForeColor = Color.MediumSlateBlue;
            ApplySaOverrideControls(message);

            foreach (var signal in group.Signals)
                flpCanSignals.Controls.Add(BuildSignalRow(message, signal));

            flpCanSignals.ResumeLayout();
            UpdateCanStartState();
        }

        /// <summary>
        /// Shows or hides the SA override checkbox + NUD and syncs them to <paramref name="message"/>.
        /// Pass <c>null</c> to hide the controls when no message is selected or it is standard CAN.
        /// </summary>
        private void ApplySaOverrideControls(MessageTxState? message)
        {
            bool visible = message != null && message.IsExtended;
            chkOverrideSa.Visible    = visible;
            nudOverrideSa.Visible    = visible;
            lblOverrideSaHex.Visible = visible;

            if (!visible) return;

            // Decode the DBC-baked SA for display
            byte dbcSa = (byte)(message!.CanId & 0xFF);

            // Suppress events while we set values
            chkOverrideSa.CheckedChanged -= null;

            bool overrideActive = message.OverrideSa.HasValue;
            chkOverrideSa.Enabled = true;
            chkOverrideSa.Checked = overrideActive;

            nudOverrideSa.Enabled = overrideActive;
            nudOverrideSa.Value   = overrideActive ? message.OverrideSa!.Value : dbcSa;

            UpdateSaHexLabel();
        }

        private void UpdateSaHexLabel()
        {
            if (lblOverrideSaHex == null || !lblOverrideSaHex.Visible) return;
            byte displaySa = chkOverrideSa.Checked ? (byte)nudOverrideSa.Value
                           : (_selectedCanMessage != null ? (byte)(_selectedCanMessage.CanId & 0xFF) : (byte)0);
            lblOverrideSaHex.Text = $"0x{displaySa:X2}";
        }

        private Control BuildSignalRow(MessageTxState message, SignalTxState signal)
        {
            var row = new Panel
            {
                Width  = 500,   // wider to accommodate mode controls
                Height = 58,
                Margin = new Padding(0, 0, 0, 2)
            };

            // ── Line 1: enable checkbox │ signal label │ value editor │ raw display ────────
            var chkEnabled = new CheckBox
            {
                Checked  = !signal.IsMuted,
                Location = new Point(0, 8),
                AutoSize = true
            };
            chkEnabled.CheckedChanged += (s, e) =>
            {
                signal.IsMuted = !chkEnabled.Checked;
                UpdateSignalNodeText(signal);
                UsrFrameBuilder.BuildDataBytes(message);
            };
            row.Controls.Add(chkEnabled);

            string signalLabel = signal.Signal.Spn.HasValue
                ? $"{signal.Signal.Name} (SPN {signal.Signal.Spn.Value})"
                : signal.Signal.Name;
            if (!string.IsNullOrWhiteSpace(signal.Signal.Unit))
                signalLabel += $" {signal.Signal.Unit}";

            row.Controls.Add(new Label
            {
                Text         = signalLabel,
                Location     = new Point(22, 9),
                Width        = 145,
                AutoEllipsis = true,
                Font         = new Font("Segoe UI", 8.5f)
            });

            var rawLabel = new Label
            {
                Location     = new Point(268, 9),
                Width        = 76,
                AutoEllipsis = true,
                Font         = new Font("Consolas", 8f),
                ForeColor    = Color.DimGray
            };
            row.Controls.Add(rawLabel);

            // Value editor (NUD or ComboBox depending on value table)
            Control valueEditor;
            if (signal.Signal.ValueTable is { Count: > 0 })
            {
                var cbo = new ComboBox
                {
                    DropDownStyle = ComboBoxStyle.DropDownList,
                    Location      = new Point(170, 5),
                    Width         = 92,
                    Font          = new Font("Segoe UI", 8.5f)
                };
                foreach (var entry in signal.Signal.ValueTable.OrderBy(v => v.Key))
                    cbo.Items.Add(new CanValueOption(entry.Key, entry.Value));
                var selected = cbo.Items.Cast<CanValueOption>().FirstOrDefault(o => o.Raw == signal.RawValue);
                if (selected != null) cbo.SelectedItem = selected;
                cbo.SelectedIndexChanged += (s, e) =>
                {
                    if (cbo.SelectedItem is not CanValueOption option) return;
                    signal.RawValue      = option.Raw;
                    signal.PhysicalValue = option.Raw * signal.Signal.Factor + signal.Signal.Offset;
                    if (SignalEncoder.TryEncodePhysical(signal.Signal, signal.PhysicalValue, out long raw, out string? err))
                    { signal.RawValue = raw; signal.Error = null; }
                    else
                    { signal.Error = err; }
                    UpdateSignalVisual(message, signal, cbo, rawLabel);
                };
                row.Controls.Add(cbo);
                UpdateSignalVisual(message, signal, cbo, rawLabel);
                valueEditor = cbo;
            }
            else
            {
                var nud = new NumericUpDown
                {
                    Location           = new Point(170, 5),
                    Width              = 92,
                    DecimalPlaces      = GetDecimalPlaces(signal.Signal.Factor),
                    Minimum            = SafeDecimal(Math.Min(signal.Signal.Min, signal.Signal.Max)),
                    Maximum            = SafeDecimal(Math.Max(signal.Signal.Min, signal.Signal.Max)),
                    Increment          = SafeIncrement(signal.Signal.Factor),
                    ThousandsSeparator = true,
                    Value              = SafeDecimal(signal.PhysicalValue),
                    Font               = new Font("Segoe UI", 8.5f)
                };
                nud.ValueChanged += (s, e) =>
                {
                    signal.PhysicalValue = (double)nud.Value;
                    UpdateSignalVisual(message, signal, nud, rawLabel);
                };
                row.Controls.Add(nud);
                UpdateSignalVisual(message, signal, nud, rawLabel);
                valueEditor = nud;
            }

            // ── Line 2: gen-mode selector ───────────────────────────────────────────────────
            bool hasRange = signal.Signal.Min < signal.Signal.Max;

            row.Controls.Add(new Label
            {
                Text      = "Mode:",
                Location  = new Point(22, 36),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 7.5f),
                ForeColor = Color.DimGray
            });

            var cboMode = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                Location      = new Point(58, 33),
                Width         = 78,
                Font          = new Font("Segoe UI", 8f)
            };
            cboMode.Items.AddRange(new object[] { "Fixed", "🎲 Random", "〜 Sine" });
            cboMode.SelectedIndex = (int)signal.GenMode;
            cboMode.Enabled = hasRange;
            row.Controls.Add(cboMode);

            var lblPeriod = new Label
            {
                Text      = "Period ms:",
                Location  = new Point(144, 36),
                AutoSize  = true,
                Font      = new Font("Segoe UI", 7.5f),
                ForeColor = Color.DimGray,
                Visible   = signal.GenMode == SignalGenMode.Sine
            };
            row.Controls.Add(lblPeriod);

            var nudPeriod = new NumericUpDown
            {
                Location  = new Point(210, 33),
                Width     = 72,
                Minimum   = 100,
                Maximum   = 300_000,
                Increment = 500,
                Value     = signal.SinePeriodMs,
                Font      = new Font("Segoe UI", 8f),
                Visible   = signal.GenMode == SignalGenMode.Sine
            };
            nudPeriod.ValueChanged += (s, e) => signal.SinePeriodMs = (int)nudPeriod.Value;
            row.Controls.Add(nudPeriod);

            cboMode.SelectedIndexChanged += (s, e) =>
            {
                signal.GenMode  = (SignalGenMode)cboMode.SelectedIndex;
                bool isSine     = signal.GenMode == SignalGenMode.Sine;
                bool isFixed    = signal.GenMode == SignalGenMode.Fixed;
                lblPeriod.Visible  = isSine;
                nudPeriod.Visible  = isSine;
                // Disable the value editor when the signal is being auto-driven
                valueEditor.Enabled = isFixed;
            };
            // Reflect initial state
            valueEditor.Enabled = signal.GenMode == SignalGenMode.Fixed;

            _canToolTip.SetToolTip(row, BuildSignalTooltip(signal.Signal) +
                (hasRange ? string.Empty : "\n⚠ Min = Max — Random/Sine unavailable"));
            return row;
        }


        private void UpdateSignalVisual(MessageTxState message, SignalTxState signal, Control editor, Label rawLabel)
        {
            if (editor is NumericUpDown nud)
                signal.PhysicalValue = (double)nud.Value;

            if (SignalEncoder.TryEncodePhysical(signal.Signal, signal.PhysicalValue, out long raw, out string? error))
            {
                signal.RawValue = raw;
                signal.Error    = null;
                rawLabel.Text   = $"raw={raw}";
                rawLabel.ForeColor = Color.DimGray;
                editor.BackColor   = Color.White;
            }
            else
            {
                signal.Error       = error;
                rawLabel.Text      = error ?? "invalid";
                rawLabel.ForeColor = Color.Crimson;
                editor.BackColor   = Color.MistyRose;
            }

            UsrFrameBuilder.BuildDataBytes(message);
            UpdateCanStartState();
            // Only refresh the selected message node instead of the entire tree
            RefreshSelectedMessageNode();
        }

        private void RefreshSelectedMessageNode()
        {
            var selectedNode = tvCanMessages.SelectedNode;
            if (selectedNode == null) return;

            // Find the message node (could be the selected node or its parent)
            TreeNode? messageNode = selectedNode.Tag is MessageTxState
                ? selectedNode
                : selectedNode.Tag is SignalNodeTag ? selectedNode.Parent : null;

            if (messageNode?.Tag is not MessageTxState msg) return;

            tvCanMessages.BeginUpdate();
            try
            {
                messageNode.Text = FormatMessageNodeText(msg);
                foreach (TreeNode signalNode in messageNode.Nodes)
                {
                    if (signalNode.Tag is SignalNodeTag signalTag)
                        signalNode.Text = FormatSignalText(signalTag.Signal);
                }
            }
            finally
            {
                tvCanMessages.EndUpdate();
            }
        }

        private void UpdateSignalNodeText(SignalTxState signal)
        {
            tvCanMessages.BeginUpdate();
            try
            {
                foreach (TreeNode parent in tvCanMessages.Nodes)
                {
                    foreach (TreeNode messageNode in parent.Nodes)
                    {
                        foreach (TreeNode signalNode in messageNode.Nodes)
                        {
                            if (signalNode.Tag is SignalNodeTag tag && ReferenceEquals(tag.Signal, signal))
                            {
                                signalNode.Text = FormatSignalText(signal);
                                return;
                            }
                        }
                    }
                }
            }
            finally
            {
                tvCanMessages.EndUpdate();
            }
        }

        private void UpdateCanUsrHeaderCount()
        {
            if (lblCanUsrCharCount == null || txtCanUsrHeader == null) return;
            int len = txtCanUsrHeader.Text.Length;
            lblCanUsrCharCount.Text      = $"{len} / {USR_META_MAX}";
            lblCanUsrCharCount.ForeColor = len > USR_META_MAX ? Color.Crimson : Color.DimGray;
            if (len > USR_META_MAX)
                lblCanUsrCharCount.Text += " ⚠️";
        }

        private async void BtnCanStart_Click(object? sender, EventArgs e)
        {
            if (!ValidateCanStart(showDialog: true)) return;

            var cfg = new CanGenConfig(
                txtCanTargetIp.Text.Trim(),
                int.Parse(txtCanTargetPort.Text.Trim()),
                txtCanSourceIp.Text.Trim(),
                txtCanUsrHeader.Text.Trim(),
                _canMessages);

            _canTxCts = new CancellationTokenSource();
            SetCanTxRunning(true);
            SetCanTxCount(0);
            CanGenLog("Starting CAN generator...");

            try
            {
                await _canTx.StartAsync(cfg, _canTxCts.Token);
            }
            finally
            {
                _canTxCts?.Dispose();
                _canTxCts = null;
                SetCanTxRunning(false);
                UpdateCanStartState();
            }
        }

        private void BtnCanStop_Click(object? sender, EventArgs e)
        {
            _canTx.Stop();
            _canTxCts?.Cancel();
        }

        private bool ValidateCanStart(bool showDialog)
        {
            string? error = GetCanStartValidationError();
            if (error == null) return true;

            if (showDialog)
                MessageBox.Show(error, "CAN Generator", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return false;
        }

        private string? GetCanStartValidationError()
        {
            if (_canDatabase == null || _canMessages.Count == 0)
                return "Please load a DBC file first.";
            if (string.IsNullOrWhiteSpace(txtCanUsrHeader.Text))
                return "USR header must not be empty.";
            if (txtCanUsrHeader.Text.Length > USR_META_MAX)
                return "USR header must be 40 characters or fewer.";
            if (!IPAddress.TryParse(txtCanTargetIp.Text.Trim(), out _))
                return "Target IP is invalid.";
            if (!IPAddress.TryParse(txtCanSourceIp.Text.Trim(), out _))
                return "Source IP is invalid.";
            if (!int.TryParse(txtCanTargetPort.Text.Trim(), out int port) || port < 1 || port > 65535)
                return "Target port must be between 1 and 65535.";

            // Only validate signals that are not muted (muted signals don't contribute to the frame)
            var invalidSignal = _canMessages
                .Where(m => m.Enabled)
                .SelectMany(m => m.Signals)
                .FirstOrDefault(s => !s.IsMuted && !string.IsNullOrEmpty(s.Error));
            if (invalidSignal != null)
                return $"Signal '{invalidSignal.Signal.Name}' has an invalid value: {invalidSignal.Error}";

            return null;
        }

        private void UpdateCanStartState()
        {
            if (btnCanStart == null) return;
            btnCanStart.Enabled = _canTxCts == null && GetCanStartValidationError() == null;
        }

        private void SetCanTxRunning(bool running)
        {
            if (this.InvokeRequired) { this.Invoke(() => SetCanTxRunning(running)); return; }
            pnlCanConfig.Enabled   = !running;
            // Keep grpCanMessages enabled during TX so users can toggle messages/signals in real time
            btnCanStart.Enabled    = !running && GetCanStartValidationError() == null;
            btnCanStop.Enabled     = running;
        }

        private void SetCanTxCount(int count)
        {
            if (this.InvokeRequired) { this.Invoke(() => SetCanTxCount(count)); return; }
            if (lblCanSentCount == null) return;
            lblCanSentCount.Text = $"Sent: {count} frames";
        }

        private void CanGenLog(string msg)
        {
            if (txtCanGenLog == null) return;
            if (this.InvokeRequired) { this.Invoke(new Action<string>(CanGenLog), msg); return; }

            string line = $"[{DateTime.Now:HH:mm:ss}] {msg}\n";
            txtCanGenLog.SelectionStart  = txtCanGenLog.TextLength;
            txtCanGenLog.SelectionLength = 0;
            txtCanGenLog.SelectionColor  =
                msg.StartsWith("✅") ? Color.LightGreen :
                msg.StartsWith("⚠️") ? Color.Orange :
                msg.StartsWith("❌") ? Color.Salmon :
                msg.StartsWith("📂") ? Color.DeepSkyBlue :
                Color.LightGray;
            txtCanGenLog.AppendText(line);
            txtCanGenLog.ScrollToCaret();
        }

        private static string BuildSignalTooltip(DbcSignal signal)
            => $"physical = raw * {signal.Factor} + {signal.Offset}, range [{signal.Min},{signal.Max}] {signal.Unit}".TrimEnd();

        private static int GetDecimalPlaces(double factor)
        {
            factor = Math.Abs(factor);
            if (factor <= 0 || factor >= 1) return 0;

            int places = 0;
            while (places < 6 && Math.Abs(factor - Math.Round(factor)) > 1e-9)
            {
                factor *= 10;
                places++;
            }

            return places;
        }

        private static decimal SafeDecimal(double value)
        {
            double clamped = Math.Max((double)decimal.MinValue, Math.Min((double)decimal.MaxValue, value));
            return (decimal)clamped;
        }

        private static decimal SafeIncrement(double factor)
        {
            decimal increment = factor == 0 ? 1m : Math.Abs(SafeDecimal(factor));
            return increment == 0 ? 1m : increment;
        }

        private sealed record SignalNodeTag(MessageTxState Message, SignalTxState Signal);
        private sealed record MuxGroupNodeTag(MessageTxState Message, int MuxValue, MultiplexGroup Group);
        private sealed record MuxParentNodeTag(MessageTxState Message);

        /// <summary>Wraps a <see cref="MessageTxState"/> for display in the Favorites combo box.</summary>
        private sealed class FavoriteEntry
        {
            public FavoriteEntry(MessageTxState message) => Message = message;
            public MessageTxState Message { get; }
            public override string ToString()
            {
                string idText = Message.IsExtended ? $"0x{Message.CanId:X8}" : $"0x{Message.CanId:X3}";
                string enabled = Message.Enabled ? string.Empty : " [off]";
                return $"⭐ {Message.Name}  {idText}{enabled}";
            }
        }

        private sealed class CanValueOption
        {
            public CanValueOption(long raw, string text)
            {
                Raw  = raw;
                Text = text;
            }

            public long Raw { get; }
            public string Text { get; }
            public override string ToString() => $"{Raw} = {Text}";
        }
    }
}
