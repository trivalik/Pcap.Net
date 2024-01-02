namespace PcapDotNet.Core.Managed.Tests
{
    internal class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Run(args);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex);
            }


            Console.WriteLine("Done.");
        }

        private static void Run(string[] args)
        {
            Console.WriteLine(PcapLibrary.Version);
            Console.WriteLine();

            var devices = LivePacketDevice.AllLocalMachine;
            foreach (var device in devices)
            {
                Console.WriteLine($" - {device.Description} ({device.Attributes})");
                foreach (var addr in device.Addresses)
                {
                    Console.WriteLine($" -- {addr.Address}");
                }
                Console.WriteLine();
            }

            var selectedDevice = devices.Where(d => d.Description?.Contains("Realtek") == true || d.Name.Contains("eth0")).FirstOrDefault();
            if (selectedDevice == null)
            {
                Console.WriteLine("No device found to operate on!");
                return;
            }

            Console.WriteLine($"Selected device: {selectedDevice.Name}; {selectedDevice.Description}");

            var com = (LivePacketCommunicator)selectedDevice.Open();
            
            var stat = com.TotalStatistics;


            Console.WriteLine(stat);


        }
    }
}
