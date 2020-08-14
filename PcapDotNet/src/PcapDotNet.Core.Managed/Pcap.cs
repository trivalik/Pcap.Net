using System;
using System.Collections.Generic;
using System.Text;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Constants and static helper methods
    /// </summary>
    public class Pcap
    {
        /// <summary>Represents the infinite number for packet captures </summary>
        internal const int InfinitePacketCount = -1;

        /* interface is loopback */
        internal const uint PCAP_IF_LOOPBACK = 0x00000001;
        internal const int MAX_PACKET_SIZE = 65536;
    }
}
