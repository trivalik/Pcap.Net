using System;
using System.Collections.Generic;
using System.Text;

namespace PcapDotNet.Core.Native
{
    internal interface ISysPal
    {
        SocketAddressFamily GetSocketAddressFamily(ushort value);
    }
}
