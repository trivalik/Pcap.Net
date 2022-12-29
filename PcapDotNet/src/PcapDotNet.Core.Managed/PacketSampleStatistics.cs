using System;
using System.Runtime.InteropServices;
using PcapDotNet.Core.Native;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Represents a statistics value when running in statistics mode.
    /// </summary>
    public sealed class PacketSampleStatistics
    {
        private DateTime _timestamp;
        private ulong _acceptedPackets;
        private ulong _acceptedBytes;

        internal PacketSampleStatistics(
            IntPtr /* const pcap_pkthdr& */ packetHeader,
            IntPtr /* const unsigned char* */ packetData)
        {
            if (packetHeader == IntPtr.Zero)
                throw new ArgumentNullException(nameof(packetHeader));

            if (packetData == IntPtr.Zero)
                throw new ArgumentNullException(nameof(packetData));

            _timestamp = Interop.Pcap.CreatePcapPacketHeader(packetHeader).Timestamp;

            _acceptedPackets = (ulong)Marshal.ReadInt64(packetData, 0);
            _acceptedBytes = (ulong)Marshal.ReadInt64(packetData, 8);
        }

        /// <summary>
        /// The time the statistics was received.
        /// </summary>
        public DateTime Timestamp => _timestamp;

        /// <summary>
        /// The number of packets received during the last interval.
        /// </summary>
        public ulong AcceptedPackets => _acceptedPackets;

        /// <summary>
        /// The number of bytes received during the last interval.
        /// </summary>
        public ulong AcceptedBytes => _acceptedBytes;

        public override string ToString()
        {
            return _timestamp + ": " + _acceptedPackets + " packets. " + _acceptedBytes + " bytes.";
        }
    }
}
