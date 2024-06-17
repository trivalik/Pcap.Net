using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for DataLinkTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class DataLinkTests
    {
        [Fact]
        public void DataLinkTest()
        {
            Assert.Equal(DataLinkKind.Ethernet.ToString(), DataLink.Ethernet.ToString());
            Assert.Equal(DataLinkKind.PointToPointProtocolWithDirection.ToString(), new DataLink(DataLinkKind.PointToPointProtocolWithDirection).ToString());
            foreach (DataLink dataLink in new[] { DataLink.Ethernet, DataLink.IpV4 })
            {
                Assert.Equal(dataLink, dataLink);
                Assert.Equal(dataLink.GetHashCode(), dataLink.GetHashCode());
                // ReSharper disable EqualExpressionComparison
                Assert.True(dataLink == dataLink);
                Assert.False(dataLink != dataLink);
                // ReSharper restore EqualExpressionComparison
            }
        }
    }
}