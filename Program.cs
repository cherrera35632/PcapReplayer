using System;
using System.Windows.Forms;
using System.Threading.Tasks;

namespace PcapReplayer
{
    class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            // CLI MODE
            if (args.Length > 0)
            {
                if (args.Length < 1)
                {
                    Console.WriteLine("Usage: PcapReplayer <path_to_pcap> [target_ip] [target_port] [speed_multiplier]");
                    return;
                }

                string pcapFile = args[0];
                string targetIpStr = args.Length > 1 ? args[1] : "127.0.0.1";
                int targetPortOverride = args.Length > 2 ? int.Parse(args[2]) : -1;
                double speedMultiplier = args.Length > 3 ? double.Parse(args[3]) : 1.0;

                var engine = new ReplayEngine();
                engine.OnLog += Console.WriteLine;
                engine.OnProgress += (c) => { if (c % 100 == 0) Console.Write("."); };
                engine.OnError += (ex) => Console.WriteLine($"\nError: {ex.Message}");
                engine.OnComplete += () => Console.WriteLine("\nDone.");

                // Synchronously wait for the task to complete
                engine.RunAsync(pcapFile, targetIpStr, targetPortOverride, speedMultiplier, false, "0.0.0.0").GetAwaiter().GetResult();
            }
            // GUI MODE
            else
            {
                Application.SetHighDpiMode(HighDpiMode.SystemAware);
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm());
            }
        }
    }
}
