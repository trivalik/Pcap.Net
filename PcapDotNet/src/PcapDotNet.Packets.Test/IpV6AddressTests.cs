using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for IpV6AddressTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class IpV6AddressTests
    {
        [Fact]
        public void IpV6AddressRandomTest()
        {
            Random random = new Random();

            for (int i = 0; i != 1000; ++i)
            {
                IpV6Address address = random.NextIpV6Address();

                Assert.Equal(address, new IpV6Address(address.ToString()));
                Assert.True(address == new IpV6Address(address.ToString()));
                Assert.False(address != new IpV6Address(address.ToString()));
                Assert.Equal(address.GetHashCode(), new IpV6Address(address.ToString()).GetHashCode());
                Assert.Equal(address, new IpV6Address(address.ToValue()));

                Assert.NotEqual(address, random.NextIpV6Address());
                Assert.False(address == random.NextIpV6Address());
                Assert.True(address != random.NextIpV6Address());
                Assert.NotEqual(address.GetHashCode(), random.NextIpV6Address().GetHashCode());

                Assert.False(address.Equals(null));
            }
        }

//        [Fact]
//        public void IpV6AddressOrderTest()
//        {
//            Assert.Equal("0.0.0.0", new IpV4Address(0).ToString());
//            Assert.Equal("0.0.0.0", IpV4Address.Zero.ToString());
//            Assert.Equal("0.0.0.1", new IpV4Address(1).ToString());
//            Assert.Equal("0.0.0.255", new IpV4Address(255).ToString());
//            Assert.Equal("0.0.1.0", new IpV4Address(256).ToString());
//            Assert.Equal("0.0.255.0", new IpV4Address(255 * 256).ToString());
//            Assert.Equal("0.1.0.0", new IpV4Address(256 * 256).ToString());
//            Assert.Equal("0.255.0.0", new IpV4Address(255 * 256 * 256).ToString());
//            Assert.Equal("1.0.0.0", new IpV4Address(256 * 256 * 256).ToString());
//            Assert.Equal("255.0.0.0", new IpV4Address((uint)255 * 256 * 256 * 256).ToString());
//            Assert.Equal("255.254.253.252", new IpV4Address((uint)255 * 256 * 256 * 256 + 254 * 256 * 256 + 253 * 256 + 252).ToString());
//        }

//        [Fact]
//        public void IpV6AddressWithBufferTest()
//        {
//            Random random = new Random();

//            for (int i = 0; i != 1000; ++i)
//            {
//                IpV4Address address = random.NextIpV4Address();

//                byte[] buffer = new byte[IpV4Address.SizeOf];

//                buffer.Write(0, address, Endianity.Big);
//                Assert.Equal(address, buffer.ReadIpV4Address(0, Endianity.Big));
//                Assert.NotEqual(address, buffer.ReadIpV4Address(0, Endianity.Small));

//                buffer.Write(0, address, Endianity.Small);
//                Assert.Equal(address, buffer.ReadIpV4Address(0, Endianity.Small));
//                Assert.NotEqual(address, buffer.ReadIpV4Address(0, Endianity.Big));
//            }
//        }

        [Fact]
        public void IpV6AddressParsingTest()
        {
            Assert.Equal(IpV6Address.Zero, new IpV6Address("0000:0000:0000:0000:0000:0000:0000:0000"));
            Assert.Equal(IpV6Address.Zero, new IpV6Address("0000:0000:0000:0000:0000:0000:0.0.0.0"));
            Assert.Equal(IpV6Address.Zero, new IpV6Address("0000:0000:0000::0000:0000:0.0.0.0"));
            Assert.Equal(IpV6Address.Zero, new IpV6Address("0000:0000:0000::0000:0.0.0.0"));
            Assert.Equal(IpV6Address.Zero, new IpV6Address("0000:0000::0000:0.0.0.0"));
            Assert.Equal(IpV6Address.Zero, new IpV6Address("0000:0000::0000"));
            Assert.Equal(IpV6Address.Zero, new IpV6Address("0000:0000::"));
            Assert.Equal(IpV6Address.Zero, new IpV6Address("0000::"));
            Assert.Equal(IpV6Address.Zero, new IpV6Address("::"));
            Assert.Equal(IpV6Address.Zero, new IpV6Address("::0.0.0.0"));

            Assert.Equal(new IpV6Address("1:2:3:4:5:6:7:8"), new IpV6Address("0001:0002:0003:0004:0005:0006:0007:0008"));
            Assert.Equal(new IpV6Address("1:2:3:4:5:6:7:8"), new IpV6Address("0001:0002:0003:0004:0005:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("1:0:3:4:5:6:7:8"), new IpV6Address("0001:0000:0003:0004:0005:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("1:0:3:4:5:6:7:8"), new IpV6Address("0001::0003:0004:0005:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:4:5:6:7:8"), new IpV6Address("0:0:0003:0004:0005:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:4:5:6:7:8"), new IpV6Address(":0:0003:0004:0005:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:4:5:6:7:8"), new IpV6Address("::0003:0004:0005:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:7:8"), new IpV6Address("0:0:0003:0000:0000:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:7:8"), new IpV6Address("0:0:0003:0:0:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:7:8"), new IpV6Address("0:0:0003::0:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:7:8"), new IpV6Address("0:0:0003::0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:7:8"), new IpV6Address("0::0003:0:0:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:7:8"), new IpV6Address("::0003:0:0:0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:7:8"), new IpV6Address(":0:0003::0006:0.7.0.8"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:7:8"), new IpV6Address(":0:0003:0:0:0006:7:8"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:7:0"), new IpV6Address(":0:0003:0:0:0006:7:"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:0:0"), new IpV6Address(":0:0003:0:0:0006::"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:0:0"), new IpV6Address(":0:0003:0:0:0006::0"));
            Assert.Equal(new IpV6Address("0:0:3:0:0:6:0:0"), new IpV6Address(":0:0003:0:0:0006::0"));
        }

        [Fact]
        public void IpV6AddressToStringTest()
        {
            Assert.Equal("0000:0000:0000:0000:0000:0000:0000:0000", IpV6Address.Zero.ToString());
        }

        [Fact]
        public void IpV6AddressNoColonTest()
        {
            Assert.Throws<ArgumentException>(() => new IpV6Address("123"));
        }

        [Fact]
        public void IpV6AddressDoubleColonsWithoutMissingColonsTest()
        {
            Assert.Throws<ArgumentException>(() => new IpV6Address("1::2:3:4:5:6:7:8"));
        }

        [Fact]
        public void IpV6AddressConstructorNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6Address(null));
        }
    }
}