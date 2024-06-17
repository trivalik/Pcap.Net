using System;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Attributes of a device.
    /// </summary>
    [Flags]
    public enum DeviceAttributes : int
    {
        /// <summary>
        /// No attributes apply.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// Interface is loopback. PCAP_IF_LOOPBACK
        /// </summary>
        Loopback = 0x00000001,

        /// <summary>
        /// Interface is up. PCAP_IF_UP
        /// </summary>
        /// <remarks>since libpcap release 1.6.1</remarks>
        Up = 0x00000002,

        /// <summary>
        /// Interface is running. PCAP_IF_RUNNING
        /// </summary>
        /// <remarks>since libpcap release 1.6.1</remarks>
        Running = 0x00000004,

        /// <summary>
        /// Interface is wireless (*NOT* necessarily Wi-Fi!). PCAP_IF_WIRELESS
        /// </summary>
        /// <remarks>since libpcap release 1.9.0</remarks>
        Wireless = 0x00000008,

        /// <summary>
        /// PCAP_IF_CONNECTION_STATUS_CONNECTED
        /// </summary>
        /// <remarks>since libpcap release 1.9.0</remarks>
        ConnectionStatusConnected = 0x00000010,

        /// <summary>
        /// PCAP_IF_CONNECTION_STATUS_DISCONNECTED
        /// </summary>
        /// <remarks>since libpcap release 1.9.0</remarks>
        ConnectionStatusDisconnected = 0x00000020,

        /// <summary>
        /// PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE
        /// </summary>
        /// <remarks>since libpcap release 1.9.0</remarks>
        ConnectionStatusNotApplicable = ConnectionStatusConnected | ConnectionStatusDisconnected,
    }
}
