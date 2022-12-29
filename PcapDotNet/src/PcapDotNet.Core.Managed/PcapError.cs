using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using PcapDotNet.Core.Native;

namespace PcapDotNet.Core
{
    internal class PcapError
    {
        public static string GetErrorMessage(PcapHandle /*pcap_t*/ pcapDescriptor)
        {

            var unmanagedPcapError = Interop.Pcap.pcap_geterr(pcapDescriptor);
            if (unmanagedPcapError == IntPtr.Zero)
                return null;
            return Marshal.PtrToStringAnsi(unmanagedPcapError);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ThrowInvalidOperation(string errorMessage, PcapHandle /*pcap_t*/ pcapDescriptor)
        {
            var fullError = new StringBuilder(errorMessage);
            if (pcapDescriptor != null && !pcapDescriptor.IsInvalid)
            {
                var pcapError = GetErrorMessage(pcapDescriptor);
                if (!string.IsNullOrEmpty(pcapError))
                {
                    fullError.Append(". Pcap Error: ");
                    fullError.Append(pcapError);
                }
            }
            throw new InvalidOperationException(fullError.ToString());
        }

    }
}
