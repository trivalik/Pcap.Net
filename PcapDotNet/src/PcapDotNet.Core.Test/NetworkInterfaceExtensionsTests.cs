using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.NetworkInformation;
using PcapDotNet.Core.Extensions;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for NetworkInterfaceExtensionsTests.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class NetworkInterfaceExtensionsTests
    {
        [Fact]
        public void GetLivePacketDeviceNull()
        {
            NetworkInterface networkInterface = null;
            Assert.Throws<ArgumentNullException>(() => networkInterface.GetLivePacketDevice());
        }
    }
}