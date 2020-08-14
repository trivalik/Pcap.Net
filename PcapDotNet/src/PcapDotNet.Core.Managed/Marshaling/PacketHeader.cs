using System;
using System.Runtime.InteropServices;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets;

namespace PcapDotNet.Core
{
    internal sealed class PacketHeader : IDisposable
    {
        private IntPtr _pcap_pkthdr = IntPtr.Zero;

        public PacketHeader(Packet packet) 
        {
            if (packet == null)
                throw new ArgumentNullException(nameof(packet));

            _pcap_pkthdr = Interop.Pcap.CreatePcapPacketHeader(packet);
        }

        public IntPtr Pointer => _pcap_pkthdr;

        public void Dispose()
        {
            Marshal.FreeHGlobal(_pcap_pkthdr);
            _pcap_pkthdr = IntPtr.Zero;
        }
    }
}
