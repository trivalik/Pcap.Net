using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Base;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for EndianitiyTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class EndianitiyTests
    {
        [Fact]
        public void UInt24Test()
        {
            UInt24 value = (UInt24)0x010203;
            byte[] buffer = new byte[UInt24.SizeOf];

            buffer.Write(0, value, Endianity.Big);
            Assert.Equal(value, buffer.ReadUInt24(0, Endianity.Big));
            Assert.Equal(0x01, buffer[0]);
            Assert.Equal(0x02, buffer[1]);
            Assert.Equal(0x03, buffer[2]);

            int offset = 0;
            buffer.Write(ref offset, value, Endianity.Big);
            Assert.Equal(value, buffer.ReadUInt24(0, Endianity.Big));
            Assert.Equal(3, offset);

            offset = 0;
            Assert.Equal(value, buffer.ReadUInt24(ref offset, Endianity.Big));
            Assert.Equal(3, offset);

            buffer.Write(0, value, Endianity.Small);
            Assert.Equal(value, buffer.ReadUInt24(0, Endianity.Small));
            Assert.Equal(0x03, buffer[0]);
            Assert.Equal(0x02, buffer[1]);
            Assert.Equal(0x01, buffer[2]);

            offset = 0;
            buffer.Write(ref offset, value, Endianity.Small);
            Assert.Equal(value, buffer.ReadUInt24(0, Endianity.Small));
            Assert.Equal(3, offset);

            offset = 0;
            Assert.Equal(value, buffer.ReadUInt24(ref offset, Endianity.Small));
            Assert.Equal(3, offset);
        }

        [Fact]
        public void UInt48Test()
        {
            UInt48 value = (UInt48)0x010203040506;
            byte[] buffer = new byte[UInt48.SizeOf];

            buffer.Write(0, value, Endianity.Big);
            Assert.Equal(value, buffer.ReadUInt48(0, Endianity.Big));
            Assert.Equal(0x01, buffer[0]);
            Assert.Equal(0x02, buffer[1]);
            Assert.Equal(0x03, buffer[2]);
            Assert.Equal(0x04, buffer[3]);
            Assert.Equal(0x05, buffer[4]);
            Assert.Equal(0x06, buffer[5]);

            int offset = 0;
            buffer.Write(ref offset, value, Endianity.Big);
            Assert.Equal(value, buffer.ReadUInt48(0, Endianity.Big));
            Assert.Equal(6, offset);

            buffer.Write(0, value, Endianity.Small);
            Assert.Equal(value, buffer.ReadUInt48(0, Endianity.Small));
            Assert.Equal(0x06, buffer[0]);
            Assert.Equal(0x05, buffer[1]);
            Assert.Equal(0x04, buffer[2]);
            Assert.Equal(0x03, buffer[3]);
            Assert.Equal(0x02, buffer[4]);
            Assert.Equal(0x01, buffer[5]);

            offset = 0;
            buffer.Write(ref offset, value, Endianity.Small);
            Assert.Equal(value, buffer.ReadUInt48(0, Endianity.Small));
            Assert.Equal(6, offset);
        }

        [Fact]
        public void UIntTest()
        {
            const uint Value = 0x01020304;
            byte[] buffer = new byte[sizeof(uint)];

            buffer.Write(0, Value, Endianity.Big);
            Assert.Equal(Value, buffer.ReadUInt(0, Endianity.Big));
            Assert.Equal(0x01, buffer[0]);
            Assert.Equal(0x02, buffer[1]);
            Assert.Equal(0x03, buffer[2]);
            Assert.Equal(0x04, buffer[3]);

            buffer.Write(0, Value, Endianity.Small);
            Assert.Equal(Value, buffer.ReadUInt(0, Endianity.Small));
            Assert.Equal(0x04, buffer[0]);
            Assert.Equal(0x03, buffer[1]);
            Assert.Equal(0x02, buffer[2]);
            Assert.Equal(0x01, buffer[3]);
        }
    }
}