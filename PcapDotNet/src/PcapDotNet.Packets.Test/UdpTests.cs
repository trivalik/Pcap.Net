using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.Packets.Transport;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for UdpTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class UdpTests
    {
        [Fact]
        public void RandomUdpTest()
        {
            EthernetLayer ethernetLayer = new EthernetLayer
                                              {
                                                  Source = new MacAddress("00:01:02:03:04:05"),
                                                  Destination = new MacAddress("A0:A1:A2:A3:A4:A5")
                                              };

            int seed = new Random().Next();
            Console.WriteLine("Seed: " + seed);
            Random random = new Random(seed);

            for (int i = 0; i != 1000; ++i)
            {
                IpV4Layer ipV4Layer = random.NextIpV4Layer(null);
                ipV4Layer.HeaderChecksum = null;
                IpV6Layer ipV6Layer = random.NextIpV6Layer(IpV4Protocol.Udp, false);

                EthernetType ethernetType = random.NextBool() ? EthernetType.IpV4 : EthernetType.IpV6;
                Layer ipLayer = (ethernetType == EthernetType.IpV4 ? (Layer)ipV4Layer : ipV6Layer);
                UdpLayer udpLayer = random.NextUdpLayer();
                udpLayer.Checksum = null;

                PayloadLayer payloadLayer = random.NextPayloadLayer(random.Next(60000));

                Packet packet = PacketBuilder.Build(DateTime.Now, ethernetLayer, ipLayer, udpLayer, payloadLayer);

                Assert.True(packet.IsValid, "IsValid");

                // Ethernet
                ethernetLayer.EtherType = ethernetType;
                Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());
                ethernetLayer.EtherType = EthernetType.None;

                // Ip
                if (ipLayer == ipV4Layer)
                {
                    // IpV4.
                    ipV4Layer.Protocol = IpV4Protocol.Udp;
                    ipV4Layer.HeaderChecksum = ((IpV4Layer)packet.Ethernet.IpV4.ExtractLayer()).HeaderChecksum;
                    Assert.Equal(ipV4Layer, packet.Ethernet.IpV4.ExtractLayer());
                    ipV4Layer.HeaderChecksum = null;
                }
                else
                {
                    // IpV6.
                    Assert.Equal(ipV6Layer, packet.Ethernet.IpV6.ExtractLayer());
                }

                // UDP
                udpLayer.Checksum = packet.Ethernet.Ip.Udp.Checksum;
                Assert.Equal(udpLayer, packet.Ethernet.Ip.Udp.ExtractLayer());
                Assert.Equal(UdpDatagram.HeaderLength + payloadLayer.Length, packet.Ethernet.Ip.Udp.TotalLength);
                Assert.True(!udpLayer.CalculateChecksum && packet.Ethernet.Ip.Udp.Checksum == 0 ||
                              udpLayer.CalculateChecksum && packet.Ethernet.Ip.IsTransportChecksumCorrect, "IsTransportChecksumCorrect");
                Assert.True(packet.Ethernet.Ip.Udp.IsChecksumOptional, "IsChecksumOptional");
                Assert.Equal(payloadLayer.Data, packet.Ethernet.Ip.Udp.Payload);
            }
        }

        [Fact]
        public void UdpChecksumTest()
        {
            Packet packet = Packet.FromHexadecimalString(
                "3352c58e71ffc4f39ec3bae508004cfe0043361200008611eec22ea2c8d11e9eb7b9520c2a33f2bbbed998980bba4404f941019404eb51880496ce00000005a87a270013a683f572c10e1504a0df15448a",
                DateTime.Now, DataLinkKind.Ethernet);

            Assert.True(packet.Ethernet.IpV4.IsTransportChecksumCorrect);
        }

        [Fact]
        public void UdpOverIpV4ZeroChecksumTest()
        {
            byte[] payload = new byte[2];
            payload.Write(0, (ushort)65498, Endianity.Big);
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                                new UdpLayer
                                                    {
                                                        CalculateChecksumValue = true
                                                    },
                                                new PayloadLayer
                                                    {
                                                        Data = new Datagram(payload)
                                                    });
            Assert.True(packet.Ethernet.IpV4.IsTransportChecksumCorrect);
            Assert.Equal(0xFFFF, packet.Ethernet.IpV4.Udp.Checksum);
        }

        [Fact]
        public void UdpOverIpV6ZeroChecksumTest()
        {
            byte[] payload = new byte[2];
            payload.Write(0, (ushort)65498, Endianity.Big);
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV6Layer(),
                                                new UdpLayer
                                                {
                                                    CalculateChecksumValue = true
                                                },
                                                new PayloadLayer
                                                {
                                                    Data = new Datagram(payload)
                                                });
            Assert.True(packet.Ethernet.IpV6.IsTransportChecksumCorrect);
            Assert.Equal(0xFFFF, packet.Ethernet.IpV6.Udp.Checksum);
        }
    }
}