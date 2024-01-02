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
        }
    }
}
