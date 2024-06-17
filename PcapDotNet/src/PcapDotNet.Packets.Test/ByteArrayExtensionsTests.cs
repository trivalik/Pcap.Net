using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for ByteArrayExtensionsTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class ByteArrayExtensionsTests
    {
        [Fact]
        public void WriteByteNullBufferTest()
        {
            Assert.Throws<ArgumentNullException>(() => ByteArrayExtensions.Write(null, 0, 1));
        }

        [Fact]
        public void WriteEnumerableNullBufferTest()
        {
            int offset = 0;
            Assert.Throws<ArgumentNullException>(() => ByteArrayExtensions.Write(null, ref offset, new byte[0]));
        }

        [Fact]
        public void WriteEnumerableNullEnumerableTest()
        {
            int offset = 0;
            Assert.Throws<ArgumentNullException>(() => new byte[0].Write(ref offset, (IEnumerable<byte>)null));
        }

        [Fact]
        public void WriteDatagramNullBufferTest()
        {
            Assert.Throws<ArgumentNullException>(() => new byte[0].Write(0, null));
        }

        [Fact]
        public void WriteRefDatagramNullBufferTest()
        {
            int offset = 0;
            Assert.Throws<ArgumentNullException>(() => new byte[0].Write(ref offset, null));
        }

        [Fact]
        public void ReadByteNullBufferTest()
        {
            Assert.Throws<ArgumentNullException>(() => ByteArrayExtensions.ReadByte(null, 0));
        }

        [Fact]
        public void ByteArrayCompareFirstNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => ByteArrayExtensions.Compare(null, 1, new byte[1], 0, 1));
        }

        [Fact]
        public void ByteArrayCompareSecondNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => new byte[1].Compare(1, null, 0, 1));
        }

        [Fact]
        public void ByteArrayFindNullArrayTest()
        {
            Assert.Throws<ArgumentNullException>(() => ByteArrayExtensions.Find(null, 1, 1, new byte[1]));
        }

        [Fact]
        public void ByteArrayFindNullOtherTest()
        {
            Assert.Throws<ArgumentNullException>(() => new byte[5].Find(1, 1, null));
        }

        [Fact]
        public void ByteArrayFindOtherCountTooBigTest()
        {
            Assert.Equal(10, new byte[10].Find(1, 1, new byte[5], 1, 2));
        }

        [Fact]
        public void ByteArraySequenceEqualNullArrayTest()
        {
            Assert.Throws<ArgumentNullException>(() => ByteArrayExtensions.SequenceEqual(null, 1, new byte[1], 0, 1));
        }

        [Fact]
        public void ByteArrayWriteNullEncodingTest()
        {
            int offset = 0;
            byte[] buffer = new byte[5];
            Assert.Throws<ArgumentNullException>(() => buffer.Write(ref offset, "123", null));
        }

        [Fact]
        public void ByteArrayUnsignedBigIntegerTest()
        {
            for (BigInteger expectedValue = 1; expectedValue <= ushort.MaxValue; expectedValue *= 10)
            {
                byte[] buffer = new byte[100];
                buffer.WriteUnsigned(5, expectedValue, 2, Endianity.Big);
                BigInteger actualValue = buffer.ReadUnsignedBigInteger(5, 2, Endianity.Big);
                Assert.Equal(expectedValue, actualValue);

                buffer = new byte[100];
                buffer.WriteUnsigned(5, expectedValue, 2, Endianity.Small);
                actualValue = buffer.ReadUnsignedBigInteger(5, 2, Endianity.Small);
                Assert.Equal(expectedValue, actualValue);
            }
            for (BigInteger expectedValue = ushort.MaxValue; expectedValue > 0; expectedValue /= 10)
            {
                byte[] buffer = new byte[100];
                buffer.WriteUnsigned(5, expectedValue, 2, Endianity.Big);
                BigInteger actualValue = buffer.ReadUnsignedBigInteger(5, 2, Endianity.Big);
                Assert.Equal(expectedValue, actualValue);

                buffer = new byte[100];
                buffer.WriteUnsigned(5, expectedValue, 2, Endianity.Small);
                actualValue = buffer.ReadUnsignedBigInteger(5, 2, Endianity.Small);
                Assert.Equal(expectedValue, actualValue);
            }
        }

        [Fact]
        public void ByteArrayReadUnsignedBigIntegerNullBufferTest()
        {
            byte[] buffer = null;
            Assert.Throws<ArgumentNullException>(() => buffer.ReadUnsignedBigInteger(0, 0, Endianity.Big));
        }

        [Fact]
        public void ByteArrayWriteUnsignedBigIntegerNullBufferTest()
        {
            byte[] buffer = null;
            Assert.Throws<ArgumentNullException>(() => buffer.WriteUnsigned(0, 0, 1, Endianity.Big));
        }

        [Fact]
        public void ByteArrayWriteUnsignedNegativeBigIntegerBufferTest()
        {
            byte[] buffer = new byte[200];
            Assert.Throws<ArgumentOutOfRangeException>(() => buffer.WriteUnsigned(0, -1, 100, Endianity.Big));
        }

        [Fact]
        public void ByteArrayULongTest()
        {
            ulong expectedValue = 10;
            byte[] buffer = new byte[8];
            buffer.Write(0, expectedValue, Endianity.Big);
            ulong actualValue = buffer.ReadULong(0, Endianity.Big);
            Assert.Equal(expectedValue, actualValue);
        }
    }
}