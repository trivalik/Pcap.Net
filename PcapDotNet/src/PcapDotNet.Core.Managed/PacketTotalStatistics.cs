using System;
using System.Text;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Statistics on capture from the start of the run. 
    /// </summary>
    public sealed class PacketTotalStatistics : IEquatable<PacketTotalStatistics>
    {
        private readonly uint _packetsReceived;
        private readonly uint _packetsDroppedByDriver;
        private readonly uint _packetsDroppedByInterface;
        private readonly uint _packetsCaptured;

        internal PacketTotalStatistics(IntPtr /* const pcap_stat&  */ statistics, int statisticsSize)
        {
            throw new NotImplementedException();
            /*
            _packetsReceived = statistics.ps_recv;
            _packetsDroppedByDriver = statistics.ps_drop;
            _packetsDroppedByInterface = statistics.ps_ifdrop;
            _packetsCaptured = (statisticsSize >= 16 
                        ? *(reinterpret_cast<const int*>(&statistics) + 3)
                        : 0);
             */
        }

        /// <summary>
        /// Number of packets transited on the network.
        /// </summary>
        public uint PacketsReceived
        {
            get => _packetsReceived;
        }

        /// <summary>
        /// Number of packets dropped by the driver.
        /// </summary>
        public uint PacketsDroppedByDriver
        {
            get => _packetsDroppedByDriver;
        }

        // TODO: Update documentation when support is added.
        /// <summary>
        /// Number of packets dropped by the interface.
        /// Not yet supported.
        /// </summary>
        public uint PacketsDroppedByInterface
        {
            get => _packetsDroppedByInterface;
        }

        /// <summary>
        /// Win32 specific. Number of packets captured, i.e number of packets that are accepted by the filter, that find place in the kernel buffer and therefore that actually reach the application.
        /// </summary>
        public uint PacketsCaptured
        {
            get => _packetsCaptured;
        }

        public bool Equals(PacketTotalStatistics other)
        {
            if (other == null)
                return false;

            return (PacketsReceived == other.PacketsReceived &&
                    PacketsDroppedByDriver == other.PacketsDroppedByDriver &&
                    PacketsDroppedByInterface == other.PacketsDroppedByInterface &&
                    PacketsCaptured == other.PacketsCaptured);
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as PacketTotalStatistics);
        }

        public override int GetHashCode()
        {
            return (int)
                (_packetsReceived ^
                _packetsDroppedByDriver ^
                _packetsDroppedByInterface ^
                _packetsCaptured);
        }

        public override string ToString()
        {
            return new StringBuilder()
            .Append("Packets Received: ")
            .Append(PacketsReceived)
            .Append(". ")
            .Append("Packets Dropped By Driver: ")
            .Append(PacketsDroppedByDriver)
            .Append(". ")
            .Append("Packets Dropped By Interface: ")
            .Append(PacketsDroppedByInterface)
            .Append(". ")
            .Append("Packets Captured: ")
            .Append(PacketsCaptured)
            .Append(".")
            .ToString();
        }
    }
}
