================================================================================
  PcapReplayer — Project Status & Roadmap
  Last updated: April 2026
  Current grade: A (GUI tool) / B+ (multi-VM deployed via script)
================================================================================

--------------------------------------------------------------------------------
  WHAT THIS TOOL DOES
--------------------------------------------------------------------------------
  GUI application (.NET 9 WinForms) that replays PCAP captures over UDP.

  Key features:
    - On load: auto-detects whether UDP payloads are PEAK or USR-CANET200 format
    - Grays out the irrelevant section (USR or PEAK) based on detection
    - Console banner: "USR DETECTED" / "PEAK DETECTED" / "MIXED" / "Unknown"
    - Override USR metadata string (pipe-delimited, injected into every USR packet)
    - PEAK CAN Gateway HTTP mock server (responds to gateway metadata queries)
    - Source IP / Target IP / Port / Speed / Loop overrides
    - Scans up to 300 UDP packets on load for classification

  Character limits (hardware-spec):
    - USR metadata string: 40 chars (USR-CANET200 hardware limit)
    - PEAK device name:    50 chars
    - PEAK user_notes:    125 chars


--------------------------------------------------------------------------------
  PROJECT STRUCTURE
--------------------------------------------------------------------------------
  C:\Projects\PcapReplayer\
  ├── PcapReplayer.csproj            Main app (WinForms, net9.0-windows)
  ├── Program.cs                     Entry point — launches MainForm
  ├── MainForm.cs                    UI: two tabs (Replay + Metadata Mock)
  │                                  Depends on IReplayEngine (not concrete class)
  ├── ReplayEngine.cs                Implements IReplayEngine
  │                                  Hot path fully optimised (see EFFICIENCY below)
  ├── IReplayEngine.cs               Interface — enables mock injection / future CLI
  ├── ReplayConfig.cs                Per-asset config record passed to RunAsync()
  │                                  Designed to be JSON-deserializable for CLI mode
  ├── IPayloadTransformer.cs         Interface + NullTransformer + UsrMetadataTransformer
  │                                  NullTransformer = singleton no-op (zero alloc)
  │                                  UsrMetadataTransformer = replaces USR header
  ├── PcapAnalyzer.cs                Scans PCAP and returns PcapAnalysisResult
  │                                  MAX_PACKETS_TO_SCAN = 300
  ├── UsrPacketHelper.cs             ALL stateless detection + injection logic
  │                                  Mirrors PeakCanParser.CanParse and
  │                                  UsrCanetParser.FindFrameStartIndex exactly
  └── MetadataMockServer.cs          PEAK HTTP mock server

  C:\Projects\PcapReplayer\PcapReplayer.Tests\
  ├── PcapReplayer.Tests.csproj
  ├── UsrPacketHelperTests.cs        38 tests: detection, injection, boundary, info byte
  ├── PcapAnalyzerTests.cs           11 tests: full classification using synthetic PCAPs
  └── PayloadTransformerTests.cs     15 tests: NullTransformer, UsrMetadataTransformer,
                                               multi-asset independence invariants
  TOTAL: 64 tests, 0 failures, ~130ms


--------------------------------------------------------------------------------
  WIRE FORMAT REFERENCE (confirmed from gateway source + datasheets)
--------------------------------------------------------------------------------

  PEAK CAN Gateway (PCAN-Gateway DR / PCAN-Ethernet Gateway):
    Offset 0-1:  Frame Length   (big-endian uint16, valid range: 20–96)
    Offset 2-3:  Message Type   (big-endian uint16)
                   0x0080 = CAN 2.0 A/B
                   0x0081 = CAN 2.0 A/B with CRC
                   0x0090 = CAN FD
                   0x0091 = CAN FD with CRC
    Offset 4-11: Flags / Channel / Reserved
    Offset 12-15: Timestamp Hi  (big-endian uint32, microseconds)
    Offset 16-19: Timestamp Lo  (big-endian uint32, microseconds)
    Offset 20:   Status flags
    Offset 21:   DLC            (0-8 for CAN 2.0, higher for FD)
    Offset 22-23: Reserved
    Offset 24-27: CAN ID        (big-endian uint32, 29-bit J1939)
    Offset 28+:  CAN Data       (DLC bytes)
    Typical size: 36 bytes (DLC=8)

  USR-CANET200:
    Two packet types:
    A) Pure metadata (registration burst):
       Pure printable ASCII, pipe-delimited:
       "AssetId|EquipType|Mfg|Database|CANName[|HardwareTypeId]"
       Max 40 chars. Sent on connection and periodically.

    B) Mixed data packet:
       [ASCII header ≤40 bytes] + [N × 13-byte CAN frames]
       CAN frame structure (13 bytes):
         Offset 0:   Info byte
                       Bit 7: FF (1=Extended 29-bit ID, 0=Standard 11-bit)
                       Bit 6: RTR (1=Remote frame)
                       Bits 5-4: Reserved — MUST be 0
                       Bits 3-0: DLC (0-8)
         Offset 1-4: CAN ID (big-endian uint32)
         Offset 5-12: CAN Data (8 bytes, padded if DLC < 8)

  DETECTION ALGORITHM (UsrPacketHelper.IsPeakFrame / IsUsrPacket):
    1. IsPeakFrame: payload ≥ 20 bytes, type at [2..3] is 0x80/0x81/0x90/0x91,
       length at [0..1] is 20-96 and ≤ payload.Length
    2. IsUsrPacket:
       - Pure ASCII + '|' in content → metadata packet
       - Non-ASCII boundary found + remaining bytes % 13 == 0
         + info byte valid (reserved bits clear, DLC 0-8) → mixed packet
    Note: IsPeakFrame is checked FIRST in PcapAnalyzer to prevent PEAK false-positives.

  REFERENCE FILES:
    C:\Projects\References\PCAN-Gateways_Developer-Documentation_eng (1).pdf
    C:\Projects\References\USR-CANET200-User-Manual_V1.0.4.01.pdf
    C:\Projects\References\final_includes_2_peakcangateway_and_usr.pcap  (mixed sample)


--------------------------------------------------------------------------------
  EFFICIENCY (hot path — ReplayEngine.cs)
--------------------------------------------------------------------------------
  - ArrayPool<byte>.Shared rented buffer: ONE buffer per replay run, returned in
    finally block. Zero per-packet heap allocation on the read path.

  - Timing: Stopwatch.GetTimestamp() (hardware counter) + HYBRID timing:
      Gap > 1.5ms → Thread.Sleep(gap - 1.5ms) to release CPU scheduler
      Final 1.5ms → Thread.SpinWait(50) for sub-millisecond precision
      Result: < 2% CPU per engine at 100Hz CAN vs 100% in prior SpinWait-only version

  - NullTransformer fast path: when no USR override is active, payload is sent
    via Socket.SendTo(rentedBuffer, payloadOffset, payloadLen) — zero extraction,
    zero allocation, zero copy.

  - Active transformer: ExtractSlice is called ONLY when UsrMetadataTransformer
    is active AND the packet is USR. PEAK packets with transformer: still zero alloc
    (TryTransform returns false → SendTo from rented buffer).

  - IPEndPoint reuse: single instance, port updated in place via UpdateEndpoint().

  - Stopwatch tick resolution cached at startup: _ticksPerUsec =
    Stopwatch.Frequency / 1_000_000.0 — no division in the hot path.


--------------------------------------------------------------------------------
  SOLID COMPLIANCE
--------------------------------------------------------------------------------
  S — Single Responsibility: Each class owns exactly one concern. ✅
  O — Open/Closed: New protocol transformer = new file implementing IPayloadTransformer.
      ReplayEngine never needs to change. ✅
  L — Liskov: NullTransformer and UsrMetadataTransformer are true substitutes. ✅
  I — Interface Segregation: IReplayEngine and IPayloadTransformer properly
      segregated. MainForm depends only on IReplayEngine. ✅
  D — Dependency Inversion: MainForm and future CLI host depend on abstractions,
      not concrete classes. ✅


--------------------------------------------------------------------------------
  WHAT IS NEEDED TO REACH A+ (future work, not current requirements)
--------------------------------------------------------------------------------
  These items are NOT implemented. They only matter for the multi-VM CLI scenario.

  ITEM 1 — CancellationToken in IReplayEngine.RunAsync
  ─────────────────────────────────────────────────────
  Current:  volatile bool _stopRequested (not composable with Task.WhenAll)
  Target:   RunAsync(ReplayConfig cfg, CancellationToken ct)
  Why:      Script running 40 engines uses CancellationTokenSource to cleanly
            cancel all instances together. Without this, you can't propagate
            Ctrl+C from the orchestrating script to child engines.
  Files:    IReplayEngine.cs, ReplayEngine.cs, MainForm.cs

  ITEM 2 — CLI / headless entry point
  ─────────────────────────────────────
  Current:  Program.cs always calls Application.Run(new MainForm())
            Cannot run on Windows Server Core or any headless VM.
  Target:   Detect args: if args present → headless CLI mode, else → WinForms
            CLI: dotnet run -- --pcap pump1.pcap --target 192.168.1.100
                              --source 10.0.0.1 --override "PUMP-001|P|R|J0|C1|3"
  Files:    Program.cs (main change), ReplayEngine.cs, ReplayConfig.cs

  ITEM 3 — Structured logging to stdout (for headless mode)
  ──────────────────────────────────────────────────────────
  Current:  OnLog fires into RichTextBox (no output in headless mode)
  Target:   Log to stdout with timestamps when running headless
            Consider: Microsoft.Extensions.Logging ILogger abstraction
  Files:    ReplayEngine.cs, Program.cs, IReplayEngine.cs

  ITEM 4 — Process exit codes
  ────────────────────────────
  Current:  All exit scenarios = exit code 0 (WinForms default)
  Target:   0 = completed cleanly, 1 = error, 2 = cancelled by script
  Why:      Script health-checking: "if %ERRORLEVEL% NEQ 0 ALERT"
  Files:    Program.cs

  ITEM 5 — ReplayConfig JSON deserialization (site.json for multi-asset CLI)
  ──────────────────────────────────────────────────────────────────────────
  Current:  ReplayConfig is a C# record, not JSON-serializable
            (IPayloadTransformer field is a polymorphic interface)
  Target:   Introduce SiteConfig / AssetConfig JSON models:
            {
              "assets": [
                { "name": "PUMP-001", "pcap": "pump.pcap",
                  "sourceIp": "10.0.0.1", "targetIp": "192.168.1.100",
                  "usrOverride": "PUMP-001|P|R|J0|C1|3", "loop": true },
                { "name": "BLEND-01", "pcap": "blender.pcap", ... }
              ]
            }
            Factory: AssetConfig → ReplayConfig (with correct IPayloadTransformer)
  Files:    SiteConfig.cs [NEW], Program.cs, ReplayConfig.cs

  ITEM 6 — Timing drift correction (for multi-hour runs)
  ────────────────────────────────────────────────────────
  Current:  Each inter-packet gap is computed independently from PCAP timestamps.
            Processing overhead accumulates over time (drift grows).
  Target:   Track cumulative expected-vs-actual time at start of each packet.
            Subtract drift from the next gap calculation.
  Files:    ReplayEngine.cs (RunCore loop)

  ITEM 7 — Transient socket error retry
  ──────────────────────────────────────
  Current:  First SocketException terminates the engine permanently.
  Target:   Retry N times with exponential backoff before propagating.
            Configuration: maxRetries=3, baseDelayMs=100
  Files:    ReplayEngine.cs (RunCore send section)

  ITEM 8 — Health/heartbeat for script orchestration
  ────────────────────────────────────────────────────
  Current:  No observable health signal from running instances.
  Target:   Write heartbeat file (e.g. pump1.heartbeat with last-packet timestamp)
            OR expose simple HTTP /health endpoint (packets sent, elapsed, status)
            Script can poll heartbeat files to confirm all 40 instances are alive.

  TOTAL: 8 items — Items 1-5 are the priority (enable the CLI multi-asset scenario).
         Items 6-8 are polish for long-running unattended deployment.


--------------------------------------------------------------------------------
  KEY DECISIONS / GOTCHAS FOR FUTURE AI SESSIONS
--------------------------------------------------------------------------------
  1. PEAK message type is 2 bytes at [2..3], NOT 1 byte at [2].
     byte[2]=0x00, byte[3]=0x80 → msgType = 0x0080 = valid CAN 2.0.
     Reading only byte[2]=0x00 gives type=0 → wrongly rejected.
     This was the bug that caused "Detection inconclusive" on all PEAK PCAPs.

  2. USR info byte validation: reserved bits 5-4 MUST be zero ((b & 0x30) == 0)
     and DLC MUST be 0-8 ((b & 0x0F) <= 8). Without this, random non-ASCII bytes
     in other protocol payloads can false-positive as USR mixed packet starts.

  3. IsPeakFrame is checked BEFORE IsUsrPacket in PcapAnalyzer to prevent
     a PEAK frame being misidentified as USR (PEAK byte[0] is 0x00 which is
     non-ASCII and could trigger FindUsrFrameStart in edge cases).

  4. The UsrMetadataTransformer replaces ONLY the ASCII header section of a
     USR mixed packet. Binary CAN frames (from FindUsrFrameStart onwards) are
     preserved byte-for-byte. For pure-ASCII metadata packets, the entire
     payload is replaced.

  5. NullTransformer is a singleton (NullTransformer.Instance). Do not instantiate.
     The hot-path check is: if (transformer is NullTransformer) → skip ExtractSlice.

  6. ArrayPool buffer is rented at start of RunCore and returned in the finally
     block. The rent size is 65536 (covers max UDP payload). It is NOT returned
     mid-loop. Ensure no reference to pktBuf escapes the using/finally scope.

  7. MainForm depends on IReplayEngine, not ReplayEngine. The concrete engine
     is instantiated in the MainForm constructor. Future CLI host should inject
     its own IReplayEngine (or the same concrete class) directly.

  8. Tests use synthetic in-memory PCAP binaries (no file I/O). The PCAP format
     built in PcapAnalyzerTests.BuildPcap() follows standard libpcap format:
     global header (24 bytes) + per-packet records (16-byte header + data).
     Link type = 1 (Ethernet). IP offset = 14, UDP offset = IP+20 = 34.
================================================================================
