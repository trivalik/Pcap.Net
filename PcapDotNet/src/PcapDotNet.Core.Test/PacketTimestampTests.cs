using System.Diagnostics.CodeAnalysis;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for PacketTimestampTests.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PacketTimestampTests
    {
        [Fact]
        public void MinMaxTests()
        {
            MoreAssert.IsBigger(PacketTimestamp.MinimumPacketTimestamp, PacketTimestamp.MaximumPacketTimestamp);
        }
    }
}