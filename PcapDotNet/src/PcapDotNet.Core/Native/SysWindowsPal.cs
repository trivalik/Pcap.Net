namespace PcapDotNet.Core.Native
{
    internal class SysWindowsPal : ISysPal
    {
        public SocketAddressFamily GetSocketAddressFamily(ushort value)
        {
            return (SocketAddressFamily)value;
        }
    }
}
