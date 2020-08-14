using System;
using System.Runtime.InteropServices;
using System.Text;
using PcapDotNet.Core.Native;

namespace PcapDotNet.Core
{
    internal class PcapError
    { 
        public static string GetErrorMessage(IntPtr /*pcap_t*/ pcapDescriptor)
        {

            var unmanagedPcapError = Interop.Pcap.pcap_geterr(pcapDescriptor);
	        if (unmanagedPcapError == IntPtr.Zero)
		        return null;
            return Marshal.PtrToStringAnsi(unmanagedPcapError);
        }
        
        public static InvalidOperationException BuildInvalidOperation(string errorMessage, IntPtr /*pcap_t*/ pcapDescriptor)
        {
            var fullError = new StringBuilder(errorMessage);
            if (pcapDescriptor != IntPtr.Zero)
            {
                var pcapError = GetErrorMessage(pcapDescriptor);
                if (!string.IsNullOrEmpty(pcapError))
                {
                    fullError.Append(". Pcap Error: ");
                    fullError.Append(pcapError);
                }
            }
            return new InvalidOperationException(fullError.ToString());
        }

    }
}
