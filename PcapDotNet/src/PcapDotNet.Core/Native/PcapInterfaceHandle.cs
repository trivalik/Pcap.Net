using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PcapDotNet.Core.Native
{
    /// <summary>
    /// Wrap a pointer/handle to a native <c>pcap_if_t</c> struct, see <see cref="PcapUnmanagedStructures.pcap_if"/>
    /// </summary>
    internal class PcapInterfaceHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public PcapInterfaceHandle() : base(true) { }

        protected override bool ReleaseHandle()
        {
            Interop.Pcap.pcap_freealldevs(handle);
            return true;
        }

        public IEnumerable<PcapUnmanagedStructures.pcap_if> GetManagedData()
        {
            var nextDevPtr = handle;
            while (nextDevPtr != IntPtr.Zero)
            {
                // Marshal pointer into a struct
                var pcap_if = Marshal.PtrToStructure<PcapUnmanagedStructures.pcap_if>(nextDevPtr);

                yield return pcap_if;

                nextDevPtr = pcap_if.Next;
            }
        }
    }
}
