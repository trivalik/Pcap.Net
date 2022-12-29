namespace PcapDotNet.Core.Native
{
    internal interface ISysPal
    {
        SocketAddressFamily GetSocketAddressFamily(ushort value);
    }
}
