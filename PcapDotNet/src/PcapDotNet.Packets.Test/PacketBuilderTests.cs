using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets.Transport;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for PacketBuilderTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PacketBuilderTests
    {
        [Fact]
        public void NoLayersTest()
        {
            Assert.Throws<ArgumentException>(() => new PacketBuilder());
        }

        [Fact]
        public void BadFirstLayerTest()
        {
            Assert.Throws<ArgumentException>(() => new PacketBuilder(new TcpLayer()));
        }

        [Fact]
        public void PacketBuilderConstructorNullTest()
        {
            ILayer[] layers = null;
            Assert.Throws<ArgumentNullException>(() => new PacketBuilder(layers));
        }
    }
}