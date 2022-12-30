using System.Runtime.InteropServices;
using PcapDotNet.Core.Native;

namespace PcapDotNet.Core
{
    /// <summary>
    /// This class holds methods for general pcap library functionality.
    /// </summary>
    public sealed class PcapLibrary
    {
        /// <summary>
        /// The Pcap library version.
        /// </summary>
        public static string Version
        {
            get
            {
                return Interop.Pcap.pcap_lib_version();
                //ToDo: error Handling?
            }

        }
    }
}
