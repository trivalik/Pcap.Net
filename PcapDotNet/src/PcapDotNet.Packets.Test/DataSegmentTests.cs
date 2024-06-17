using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for DataSegmentTests.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class DataSegmentTests
    {
        [Fact]
        public void ToHexadecimalStringTest()
        {
            byte[] input = new byte[] {1, 2, 3, 4, 5, 6};
            Assert.Equal(HexEncoding.Instance.GetString(input), new DataSegment(input).ToHexadecimalString());
        }

        [Fact]
        public void DecodeNullEncodingTest()
        {
            Assert.Throws<ArgumentNullException>(() => new DataSegment(new byte[1]).Decode(null));
        }
   }
}