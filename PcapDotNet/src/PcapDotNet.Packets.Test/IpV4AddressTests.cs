using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for IpV4AddressTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class IpV4AddressTests
    {
        [Fact]
        public void IpV4AddressRandomTest()
        {
            Assert.Equal(IpV4Address.AllHostsGroupAddress, new IpV4Address("224.0.0.1"));

            Random random = new Random();

            for (int i = 0; i != 1000; ++i)
            {
                IpV4Address address = random.NextIpV4Address();

                Assert.Equal(address, new IpV4Address(address.ToString()));
                Assert.True(address == new IpV4Address(address.ToString()));
                Assert.False(address != new IpV4Address(address.ToString()));
                Assert.Equal(address.GetHashCode(), new IpV4Address(address.ToString()).GetHashCode());
                Assert.Equal(address, new IpV4Address(address.ToValue()));
                
                Assert.NotEqual(address, random.NextIpV4Address());
                Assert.False(address == random.NextIpV4Address());
                Assert.True(address != random.NextIpV4Address());
                Assert.NotEqual(address.GetHashCode(), random.NextIpV4Address().GetHashCode());

                Assert.False(address.Equals(null));
            }
        }

        [Fact]
        public void IpV4AddressOrderTest()
        {
            Assert.Equal("0.0.0.0", new IpV4Address(0).ToString());
            Assert.Equal("0.0.0.0", IpV4Address.Zero.ToString());
            Assert.Equal("0.0.0.1", new IpV4Address(1).ToString());
            Assert.Equal("0.0.0.255", new IpV4Address(255).ToString());
            Assert.Equal("0.0.1.0", new IpV4Address(256).ToString());
            Assert.Equal("0.0.255.0", new IpV4Address(255 * 256).ToString());
            Assert.Equal("0.1.0.0", new IpV4Address(256 * 256).ToString());
            Assert.Equal("0.255.0.0", new IpV4Address(255 * 256 * 256).ToString());
            Assert.Equal("1.0.0.0", new IpV4Address(256 * 256 * 256).ToString());
            Assert.Equal("255.0.0.0", new IpV4Address((uint)255 * 256 * 256 * 256).ToString());
            Assert.Equal("255.254.253.252", new IpV4Address((uint)255 * 256 * 256 * 256 + 254 * 256 * 256 + 253 * 256 + 252).ToString());
        }

        [Fact]
        public void IpV4AddressWithBufferTest()
        {
            Random random = new Random();

            for (int i = 0; i != 1000; ++i)
            {
                IpV4Address address = random.NextIpV4Address();

                byte[] buffer = new byte[IpV4Address.SizeOf];

                buffer.Write(0, address, Endianity.Big);
                Assert.Equal(address, buffer.ReadIpV4Address(0, Endianity.Big));
                Assert.NotEqual(address, buffer.ReadIpV4Address(0, Endianity.Small));

                buffer.Write(0, address, Endianity.Small);
                Assert.Equal(address, buffer.ReadIpV4Address(0, Endianity.Small));
                Assert.NotEqual(address, buffer.ReadIpV4Address(0, Endianity.Big));
            }
        }

        [Fact]
        public void IpV4AddressConstructorNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV4Address(null));
        }

        [Fact]
        public void TryParseTest()
        {
            IpV4Address actual;
            Assert.True(IpV4Address.TryParse("1.2.3.4", out actual));
            Assert.Equal(new IpV4Address("1.2.3.4"), actual);

            Assert.False(IpV4Address.TryParse(null, out actual));
            Assert.False(IpV4Address.TryParse("1", out actual));
            Assert.False(IpV4Address.TryParse("1.", out actual));
            Assert.False(IpV4Address.TryParse("1.2", out actual));
            Assert.False(IpV4Address.TryParse("1.2.", out actual));
            Assert.False(IpV4Address.TryParse("1.2.3", out actual));
            Assert.False(IpV4Address.TryParse("1.2.3.", out actual));
            Assert.False(IpV4Address.TryParse("1.2.3.a", out actual));
            Assert.False(IpV4Address.TryParse("a.2.3.4", out actual));
            Assert.False(IpV4Address.TryParse("1.a.3.4", out actual));
            Assert.False(IpV4Address.TryParse("1.2.a.4", out actual));
            Assert.False(IpV4Address.TryParse("1.2.3.a", out actual));
            Assert.False(IpV4Address.TryParse("256.2.3.4", out actual));
        }
    }
}
