using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for VLanTaggedFrameTests.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class VLanTaggedFrameTests
    {
        [Fact]
        public void RandomVLanTaggedFrameTest()
        {
            Random random = new Random();

            for (int i = 0; i != 1000; ++i)
            {
                EthernetLayer ethernetLayer = random.NextEthernetLayer(EthernetType.None);
                VLanTaggedFrameLayer vLanTaggedFrameLayer = random.NextVLanTaggedFrameLayer();
                int payloadLength = random.Next(1500);
                PayloadLayer payloadLayer = new PayloadLayer
                {
                    Data = random.NextDatagram(payloadLength),
                };
                Packet packet = PacketBuilder.Build(DateTime.Now, ethernetLayer, vLanTaggedFrameLayer, payloadLayer);

                ethernetLayer.EtherType = EthernetType.VLanTaggedFrame;

                // Test output.
                Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());
                Assert.Equal(vLanTaggedFrameLayer, packet.Ethernet.VLanTaggedFrame.ExtractLayer());
                Assert.Equal(vLanTaggedFrameLayer.GetHashCode(), packet.Ethernet.VLanTaggedFrame.ExtractLayer().GetHashCode());
                Assert.NotEqual(random.NextVLanTaggedFrameLayer().GetHashCode(), packet.Ethernet.VLanTaggedFrame.ExtractLayer().GetHashCode());
                Assert.Equal(vLanTaggedFrameLayer.TagControlInformation, packet.Ethernet.VLanTaggedFrame.TagControlInformation);
                Assert.Equal(payloadLayer.Data, packet.Ethernet.VLanTaggedFrame.Payload);
            }
        }

        [Fact]
        public void AutoSetEtherTypeTest()
        {
            Random random = new Random();
            EthernetLayer ethernetLayer = random.NextEthernetLayer(EthernetType.None);
            VLanTaggedFrameLayer vLanTaggedFrameLayer = random.NextVLanTaggedFrameLayer(EthernetType.None);
            IpV4Layer ipV4Layer = random.NextIpV4Layer();
            Packet packet = PacketBuilder.Build(DateTime.Now, ethernetLayer, vLanTaggedFrameLayer, ipV4Layer);

            ethernetLayer.EtherType = EthernetType.VLanTaggedFrame;
            vLanTaggedFrameLayer.EtherType = EthernetType.IpV4;

            // Test equality.
            Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());
            Assert.Equal(EthernetType.IpV4, packet.Ethernet.VLanTaggedFrame.EtherType);
            Assert.Equal(vLanTaggedFrameLayer, packet.Ethernet.VLanTaggedFrame.ExtractLayer());
            ipV4Layer.HeaderChecksum = packet.Ethernet.VLanTaggedFrame.IpV4.HeaderChecksum;
            Assert.Equal(ipV4Layer, packet.Ethernet.VLanTaggedFrame.IpV4.ExtractLayer());
        }

        [Fact]
        public void DontAutoSetEthernetDestinationTest()
        {
            Random random = new Random();
            EthernetLayer ethernetLayer = random.NextEthernetLayer(EthernetType.None);
            ethernetLayer.Destination = MacAddress.Zero;
            VLanTaggedFrameLayer vLanTaggedFrameLayer = random.NextVLanTaggedFrameLayer();
            Packet packet = PacketBuilder.Build(DateTime.Now, ethernetLayer, vLanTaggedFrameLayer);

            ethernetLayer.EtherType = EthernetType.VLanTaggedFrame;

            // Test equality.
            Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());
            Assert.Equal(vLanTaggedFrameLayer, packet.Ethernet.VLanTaggedFrame.ExtractLayer());
        }
    }
}