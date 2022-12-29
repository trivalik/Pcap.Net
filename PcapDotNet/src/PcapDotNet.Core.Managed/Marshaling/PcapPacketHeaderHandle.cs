using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets;

namespace PcapDotNet.Core
{
    internal sealed class PcapPacketHeaderHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public PcapPacketHeaderHandle(Packet packet) : base(true)
        {
            if (packet == null)
                throw new ArgumentNullException(nameof(packet));

            SetHandle(Interop.Pcap.CreatePcapPacketHeaderHandle(packet));
        }

        public IntPtr Pointer => handle;

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }
}
