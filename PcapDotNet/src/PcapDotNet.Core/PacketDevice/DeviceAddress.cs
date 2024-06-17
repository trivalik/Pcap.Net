using PcapDotNet.Core.Native;
using System;
using System.Text;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Representation of an interface address.
    /// </summary>
    public sealed class DeviceAddress
    {
        private readonly SocketAddress _address;
        private readonly SocketAddress _netmask;
        private readonly SocketAddress _broadcast;
        private readonly SocketAddress _destination;

        internal DeviceAddress(PcapUnmanagedStructures.pcap_addr pcap_addr, SocketAddressFamily socketAddressFamily)
        {
            switch (socketAddressFamily)
            {
                case SocketAddressFamily.Internet:
                    if (pcap_addr.Addr != IntPtr.Zero)
                        _address = new IpV4SocketAddress(pcap_addr.Addr);
                    if (pcap_addr.Netmask != IntPtr.Zero)
                        _netmask = new IpV4SocketAddress(pcap_addr.Netmask);
                    if (pcap_addr.Broadaddr != IntPtr.Zero)
                        _broadcast = new IpV4SocketAddress(pcap_addr.Broadaddr);
                    if (pcap_addr.Dstaddr != IntPtr.Zero)
                        _destination = new IpV4SocketAddress(pcap_addr.Dstaddr);
                    break;

                case SocketAddressFamily.Internet6:
                    if (pcap_addr.Addr != IntPtr.Zero)
                        _address = new IpV6SocketAddress(pcap_addr.Addr);
                    if (pcap_addr.Netmask != IntPtr.Zero)
                        _netmask = new IpV6SocketAddress(pcap_addr.Netmask);
                    if (pcap_addr.Broadaddr != IntPtr.Zero)
                        _broadcast = new IpV6SocketAddress(pcap_addr.Broadaddr);
                    if (pcap_addr.Dstaddr != IntPtr.Zero)
                        _destination = new IpV6SocketAddress(pcap_addr.Dstaddr);
                    break;

                default:
                    throw new NotImplementedException("Device of family " + socketAddressFamily.ToString() + " is unsupported");
            }
        }

        /// <summary>
        /// The Device Address.
        /// </summary>
        public SocketAddress Address => _address;

        /// <summary>
        /// if not null, the netmask corresponding to the address in Address. 
        /// </summary>
        public SocketAddress Netmask => _netmask;

        /// <summary>
        /// if not null, the broadcast address corresponding to the address in Address; may be null if the interface doesn't support broadcasts.
        /// </summary>
        public SocketAddress Broadcast => _broadcast;

        /// <summary>
        /// if not null, the destination address corresponding to the address in Address; may be null if the interface isn't a point-to-point interface 
        /// </summary>
        public SocketAddress Destination => _destination;

        public override string ToString()
        {
            var result = new StringBuilder();

            AppendSocketAddressString(result, Address, "Address");
            AppendSocketAddressString(result, Netmask, "Netmask");
            AppendSocketAddressString(result, Broadcast, "Broadcast");
            AppendSocketAddressString(result, Destination, "Destination");

            return result.ToString();
        }

        private static void AppendSocketAddressString(StringBuilder sb, SocketAddress socketAddress, string title)
        {
            if (socketAddress != null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(title);
                sb.Append(": ");
                sb.Append(socketAddress);
            }
        }
    }
}
