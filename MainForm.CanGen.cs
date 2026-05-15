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

            grpCanMessages = new GroupBox
            {
                Text      = "Messages (PGN → Message → Signal)",
                Location  = new Point(10, 124),
                Size      = new Size(634, 350),
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
            pnlCanDetailHeader = new Panel { Dock = DockStyle.Top, Height = 58 };
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
                if (_selectedCanMessage.IsMultiplexed)
                    _selectedCanMessage.MuxRoundRobinIntervalMs = (int)nudCanMsgRate.Value;
                else
                    _selectedCanMessage.PeriodMs = (int)nudCanMsgRate.Value;
            };
            pnlCanDetailHeader.Controls.Add(nudCanMsgRate);

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

            tab.Controls.AddRange(new Control[]
            {
                pnlCanConfig,
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

        private void RebuildCanTree()
        {
            tvCanMessages.BeginUpdate();
            try
            {
                tvCanMessages.Nodes.Clear();
                _selectedCanMessage = null;
                flpCanSignals.Controls.Clear();
                chkCanMsgEnabled.Enabled = false;
                nudCanMsgRate.Enabled    = false;
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
                ShowMessageDetails(muxParentTag.Message);
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
                lblCanMsgInfo.Text       = "Select a CAN message from the tree.";
                lblCanMsgInfo.ForeColor  = Color.DimGray;
                flpCanSignals.ResumeLayout();
                return;
            }

            chkCanMsgEnabled.Text    = "Enable message";
            chkCanMsgEnabled.Enabled = true;
            chkCanMsgEnabled.Checked = message.Enabled;
            chkCanMsgEnabled.Tag     = null; // not bound to a mux group
            nudCanMsgRate.Enabled    = true;
            nudCanMsgRate.Value      = message.IsMultiplexed ? message.MuxRoundRobinIntervalMs : message.PeriodMs;
            string infoText = $"{message.Name}  ID=0x{message.CanId:X8}  DLC={message.Dlc}";
            if (message.IsMultiplexed && message.MultiplexGroups != null)
            {
                int enabledCount = message.MultiplexGroups.Values.Count(g => g.Enabled);
                int totalMs = enabledCount * message.MuxRoundRobinIntervalMs;
                infoText += $"  [{enabledCount} mux groups × {message.MuxRoundRobinIntervalMs}ms = {totalMs}ms cycle]";
            }
            lblCanMsgInfo.Text       = infoText;
            lblCanMsgInfo.ForeColor  = Color.Black;

            foreach (var signal in message.Signals)
                flpCanSignals.Controls.Add(BuildSignalRow(message, signal));

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

            // Rate controls the mux round-robin interval (time between successive mux options)
            nudCanMsgRate.Enabled = true;
            nudCanMsgRate.Value   = message.MuxRoundRobinIntervalMs;

            int enabledCount = message.MultiplexGroups?.Values.Count(g => g.Enabled) ?? 0;
            int totalMs = enabledCount * message.MuxRoundRobinIntervalMs;
            lblCanMsgInfo.Text = $"{message.Name}  Mux m{muxValue}  ({group.Signals.Count} signals)  " +
                                 $"[{enabledCount} groups × {message.MuxRoundRobinIntervalMs}ms = {totalMs}ms cycle]";
            lblCanMsgInfo.ForeColor = Color.MediumSlateBlue;

            foreach (var signal in group.Signals)
                flpCanSignals.Controls.Add(BuildSignalRow(message, signal));

            flpCanSignals.ResumeLayout();
            UpdateCanStartState();
        }

        private Control BuildSignalRow(MessageTxState message, SignalTxState signal)
        {
            var row = new Panel
            {
                Width  = 348,
                Height = 34,
                Margin = new Padding(0, 0, 0, 4)
            };

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
                Text     = signalLabel,
                Location = new Point(22, 9),
                Width    = 145,
                AutoEllipsis = true,
                Font     = new Font("Segoe UI", 8.5f)
            });

            var rawLabel = new Label
            {
                Location  = new Point(268, 9),
                Width     = 76,
                AutoEllipsis = true,
                Font      = new Font("Consolas", 8f),
                ForeColor = Color.DimGray
            };
            row.Controls.Add(rawLabel);

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
                    if (SignalEncoder.TryEncodePhysical(signal.Signal, signal.PhysicalValue, out long raw, out string? error))
                    {
                        signal.RawValue = raw;
                        signal.Error    = null;
                    }
                    else
                    {
                        signal.Error = error;
                    }
                    UpdateSignalVisual(message, signal, cbo, rawLabel);
                };
                row.Controls.Add(cbo);
                UpdateSignalVisual(message, signal, cbo, rawLabel);
            }
            else
            {
                var nud = new NumericUpDown
                {
                    Location          = new Point(170, 5),
                    Width             = 92,
                    DecimalPlaces     = GetDecimalPlaces(signal.Signal.Factor),
                    Minimum           = SafeDecimal(Math.Min(signal.Signal.Min, signal.Signal.Max)),
                    Maximum           = SafeDecimal(Math.Max(signal.Signal.Min, signal.Signal.Max)),
                    Increment         = SafeIncrement(signal.Signal.Factor),
                    ThousandsSeparator = true,
                    Value             = SafeDecimal(signal.PhysicalValue),
                    Font              = new Font("Segoe UI", 8.5f)
                };
                nud.ValueChanged += (s, e) =>
                {
                    signal.PhysicalValue = (double)nud.Value;
                    UpdateSignalVisual(message, signal, nud, rawLabel);
                };
                row.Controls.Add(nud);
                UpdateSignalVisual(message, signal, nud, rawLabel);
            }

            _canToolTip.SetToolTip(row, BuildSignalTooltip(signal.Signal));
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
