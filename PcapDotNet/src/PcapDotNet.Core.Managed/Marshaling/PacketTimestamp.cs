using System;
using PcapDotNet.Base;
using PcapDotNet.Core.Native;

namespace PcapDotNet.Core
{
    public sealed class PacketTimestamp
    {
        static PacketTimestamp()
        {
            MinimumPacketTimestamp = Interop.UnixEpoch.AddSeconds(int.MinValue).AddTicks(int.MinValue * TimeSpanExtensions.TicksPerMicrosecond);
            MaximumPacketTimestamp = Interop.UnixEpoch.AddSeconds(int.MaxValue).AddTicks(int.MaxValue * TimeSpanExtensions.TicksPerMicrosecond);

        }

        /// <summary>
        /// The minimum legal timestamp to put in a packet.
        /// </summary>
        public static DateTime MinimumPacketTimestamp { get; }

        /// <summary>
        /// The maximum legal timestamp to put in a packet.
        /// </summary>
        public static DateTime MaximumPacketTimestamp { get; }

        internal static DateTime PcapTimestampToDateTime(PcapUnmanagedStructures.timeval_windows ts)
        {
            return Interop.UnixEpoch.AddSeconds(ts.tv_sec).AddMicroseconds(ts.tv_usec).ToLocalTime();
        }

        internal static DateTime PcapTimestampToDateTime(PcapUnmanagedStructures.timeval_unix ts)
        {
            return Interop.UnixEpoch.AddSeconds((ulong)ts.tv_sec).AddMicroseconds((ulong)ts.tv_usec).ToLocalTime();
        }
    }
}
