using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for SerialNumber32Test
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class SerialNumber32Test
    {
        [Fact]
        public void SimpleTest()
        {
            Assert.Equal<SerialNumber32>(1, 1);
            Assert.NotEqual<SerialNumber32>(1, 2);
            MoreAssert.IsBigger(1, 2);
            MoreAssert.IsSmaller(2, 1);

            SerialNumber32 serialNumber = 1;
            serialNumber = serialNumber.Add(10);
            Assert.Equal<SerialNumber32>(11, serialNumber);

            serialNumber = serialNumber.Add(((uint)1 << 31) - 1);
            Assert.Equal<SerialNumber32>(2147483658, serialNumber);
            MoreAssert.IsSmaller<SerialNumber32>(1, serialNumber);
            MoreAssert.IsBigger<SerialNumber32>(20, serialNumber);

            serialNumber = serialNumber.Add(((uint)1 << 31) - 1);
            Assert.Equal<SerialNumber32>(9, serialNumber);

            Assert.True(new SerialNumber32(1) < new SerialNumber32(2));
            Assert.True(new SerialNumber32(2) > new SerialNumber32(1));
            // ReSharper disable EqualExpressionComparison
            Assert.False(new SerialNumber32(1) < new SerialNumber32(1));
            Assert.False(new SerialNumber32(1) > new SerialNumber32(1));
            // ReSharper restore EqualExpressionComparison
            Assert.True(new SerialNumber32(2) != new SerialNumber32(1));
            Assert.False(new SerialNumber32(1) != new SerialNumber32(0).Add(1));
            Assert.True(new SerialNumber32(2) == new SerialNumber32(1).Add(1));
            Assert.False(new SerialNumber32(1).Equals(1.0));

            Assert.Equal("1", new SerialNumber32(1).ToString());
        }

        [Fact]
        public void OverflowAddTest()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                SerialNumber32 serialNumber = 1;
                serialNumber = serialNumber.Add((uint)1 << 31);
            });
        }

    }
}