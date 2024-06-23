using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Core.Extensions;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for LivePacketDeviceExtensionsTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class LivePacketDeviceExtensionsTests
    {
        [Fact]
        public void GetNetworkInterfaceNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => LivePacketDeviceExtensions.GetNetworkInterface(null));
        }
        
        [Fact(Skip ="NullRefExcetion for loopback device")]
        public void GetMacAddressTest()
        {
            foreach (LivePacketDevice device in LivePacketDevice.AllLocalMachine)
            {
                _ = device.GetMacAddress();
            }
        }

        [Fact]
        public void GetGuidNullDeviceTest()
        {
            Assert.Throws<ArgumentNullException>(() => (null as LivePacketDevice).GetGuid());
        }
    }
}