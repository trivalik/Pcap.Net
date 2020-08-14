using System;
using System.Collections.Generic;
using System.Text;

namespace PcapDotNet.Core
{
    public sealed class PacketTimestamp
    {
        private static DateTime _minimumPacketTimestamp;
        private static DateTime _maximumPacketTimestamp;
        
        /// <summary>
        /// The minimum legal timestamp to put in a packet.
        /// </summary>
        public static DateTime MinimumPacketTimestamp
        {
            get { return _minimumPacketTimestamp; }
        }

        /// <summary>
        /// The maximum legal timestamp to put in a packet.
        /// </summary>
        public static DateTime MaximumPacketTimestamp
        {
            get { return _maximumPacketTimestamp; }
        }
    }
}
