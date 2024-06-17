using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for PppFrameCheckSequenceCalculatorTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PppFrameCheckSequenceCalculatorTests
    {
        [Fact]
        public void RandomFcs16Test()
        {
            Random random = new Random();
            for (int i = 0; i != 100; ++i)
            {
                DataSegment data = random.NextDataSegment(random.Next(1000));
                ushort fcs = PointToPointProtocolFrameCheckSequenceCalculator.CalculateFrameCheckSequence16(data);
            }
        }

        [Fact]
        public void GoodFcs16Test()
        {
            const ushort GoodFcs16 = 0xf0b8;

            for (int fcs16Value = 0; fcs16Value <= ushort.MaxValue; ++fcs16Value)
            {
                ushort extraValue = (ushort)(fcs16Value ^ 0xffff); // Complement.
                Assert.Equal(GoodFcs16, PointToPointProtocolFrameCheckSequenceCalculator.CalculateFrameCheckSequence16((ushort)fcs16Value, new[] { (byte)extraValue, (byte)(extraValue >> 8) }));
            }
        }
    }
}