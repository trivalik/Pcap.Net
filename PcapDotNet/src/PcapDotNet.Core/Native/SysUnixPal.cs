﻿using System;

namespace PcapDotNet.Core.Native
{
    internal class SysUnixPal : ISysPal
    {
        public SocketAddressFamily GetSocketAddressFamily(ushort value)
        {
            switch (value)
            {
                case 0 /* AF_UNSPEC */:
                    return SocketAddressFamily.Unspecified;

                case 1 /* AF_UNIX */:
                    return SocketAddressFamily.Unix;

                case 2 /* AF_INET */:
                    return SocketAddressFamily.Internet;

                case 10 /* AF_INET6 */:
                    return SocketAddressFamily.Internet6;

                case 17: /* AF_PACKET */
                    return SocketAddressFamily.Packet;

                default:
                    throw new PlatformNotSupportedException("SocketAddressFamily " + value + " is not supported");
            }
        }
    }
}
