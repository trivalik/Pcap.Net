using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for MacAddressTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class MacAddressTests
    {
        [Fact]
        public void MacAddressTest()
        {
            Random random = new Random();

            for (int i = 0; i != 1000; ++i)
            {
                MacAddress macAddress = random.NextMacAddress();

                Assert.NotNull(macAddress.ToString());
                Assert.Equal(macAddress, new MacAddress(macAddress.ToString()));
                Assert.NotEqual(macAddress, random.NextMacAddress());
                Assert.True(macAddress == new MacAddress(macAddress.ToString()));
                Assert.Equal(macAddress.GetHashCode(), new MacAddress(macAddress.ToString()).GetHashCode());
                Assert.True(macAddress != random.NextMacAddress());
                Assert.NotEqual(macAddress.GetHashCode(), random.NextMacAddress().GetHashCode());
            }
        }

        [Fact]
        public void MacAddressWithBufferTest()
        {
            Random random = new Random();
            MacAddress address = random.NextMacAddress();

            byte[] buffer = new byte[MacAddress.SizeOf];

            buffer.Write(0, address, Endianity.Big);
            Assert.Equal(address, buffer.ReadMacAddress(0, Endianity.Big));
            Assert.NotEqual(address, buffer.ReadMacAddress(0, Endianity.Small));

            int offset = 0;
            buffer.Write(ref offset, address, Endianity.Big);
            Assert.Equal(address, buffer.ReadMacAddress(0, Endianity.Big));
            Assert.Equal(6, offset);

            offset = 0;
            Assert.Equal(address, buffer.ReadMacAddress(ref offset, Endianity.Big));
            Assert.Equal(MacAddress.SizeOf, offset);

            buffer.Write(0, address, Endianity.Small);
            Assert.Equal(address, buffer.ReadMacAddress(0, Endianity.Small));
            Assert.NotEqual(address, buffer.ReadMacAddress(0, Endianity.Big));

            offset = 0;
            buffer.Write(ref offset, address, Endianity.Small);
            Assert.Equal(address, buffer.ReadMacAddress(0, Endianity.Small));
            Assert.Equal(6, offset);

            offset = 0;
            Assert.Equal(address, buffer.ReadMacAddress(ref offset, Endianity.Small));
            Assert.Equal(MacAddress.SizeOf, offset);
        }

        [Fact]
        public void MacAddressBadStringErrorTest()
        {
            Assert.Throws<ArgumentException>(() => new MacAddress("12:34:56:78"));
        }

        [Fact]
        public void MacAddressConstructorNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => new MacAddress(null));
        }
    }
}