using Microsoft.Win32.SafeHandles;

namespace PcapDotNet.Core.Native
{
    /// <summary>
    /// Wrap a pointer/handle to a native <c>pcap_t</c> struct
    /// </summary>
    internal class PcapHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public PcapHandle() : base(ownsHandle: true) { }

        protected override bool ReleaseHandle()
        {
            Interop.Pcap.pcap_close(handle);
            return true;
        }
    }
}
