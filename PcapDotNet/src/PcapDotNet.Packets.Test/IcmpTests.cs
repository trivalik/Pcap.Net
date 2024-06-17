using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for IcmpTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class IcmpTests
    {
        [Fact]
        public void RandomIcmpTest()
        {
            EthernetLayer ethernetLayer = new EthernetLayer
                                              {
                                                  Source = new MacAddress("00:01:02:03:04:05"),
                                                  Destination = new MacAddress("A0:A1:A2:A3:A4:A5")
                                              };

            int seed = new Random().Next();
            Console.WriteLine("Seed: " + seed);
            Random random = new Random(seed);

            for (int i = 0; i != 2000; ++i)
            {
                IpV4Layer ipV4Layer = random.NextIpV4Layer(null);
                ipV4Layer.HeaderChecksum = null;
                Layer ipLayer = random.NextBool() ? (Layer)ipV4Layer : random.NextIpV6Layer(IpV4Protocol.InternetControlMessageProtocol, false);

                IcmpLayer icmpLayer = random.NextIcmpLayer();
                icmpLayer.Checksum = null;
                if (icmpLayer.MessageType == IcmpMessageType.DestinationUnreachable && 
                    icmpLayer.MessageTypeAndCode != IcmpMessageTypeAndCode.DestinationUnreachableFragmentationNeededAndDoNotFragmentSet)
                {
                    ((IcmpDestinationUnreachableLayer)icmpLayer).NextHopMaximumTransmissionUnit = 0;
                }

                IEnumerable<ILayer> icmpPayloadLayers = random.NextIcmpPayloadLayers(icmpLayer);

                int icmpPayloadLength = icmpPayloadLayers.Select(layer => layer.Length).Sum();

                switch (icmpLayer.MessageType)
                {
                    case IcmpMessageType.ParameterProblem:
                        if (icmpPayloadLength % 4 != 0)
                            icmpPayloadLayers = icmpPayloadLayers.Concat(new[] {new PayloadLayer {Data = random.NextDatagram(4 - icmpPayloadLength % 4)}});
                        icmpPayloadLength = icmpPayloadLayers.Select(layer => layer.Length).Sum();
                        IcmpParameterProblemLayer icmpParameterProblemLayer = (IcmpParameterProblemLayer)icmpLayer;
                        icmpParameterProblemLayer.Pointer = (byte)(icmpParameterProblemLayer.Pointer % icmpPayloadLength);
                        icmpParameterProblemLayer.OriginalDatagramLength = icmpPayloadLength - icmpPayloadLayers.First().Length;
                        break;

                    case IcmpMessageType.SecurityFailures:
                        ((IcmpSecurityFailuresLayer)icmpLayer).Pointer %= (ushort)icmpPayloadLength;
                        break;
                }

                PacketBuilder packetBuilder = new PacketBuilder(new ILayer[] { ethernetLayer, ipLayer, icmpLayer }.Concat(icmpPayloadLayers));

                Packet packet = packetBuilder.Build(DateTime.Now);
                Assert.True(packet.IsValid, "IsValid");

                byte[] buffer = (byte[])packet.Buffer.Clone();
                buffer.Write(ethernetLayer.Length + ipLayer.Length, random.NextDatagram(icmpLayer.Length));
                Packet illegalPacket = new Packet(buffer, DateTime.Now, packet.DataLink);
                Assert.False(illegalPacket.IsValid, "IsInvalid");
                if (illegalPacket.Ethernet.Ip.Icmp is IcmpUnknownDatagram)
                {
                    byte[] icmpBuffer = new byte[illegalPacket.Ethernet.Ip.Icmp.ExtractLayer().Length];
                    ILayer layer = illegalPacket.Ethernet.Ip.Icmp.ExtractLayer();
                    layer.Write(icmpBuffer,0,icmpBuffer.Length, null,null);
                    layer.Finalize(icmpBuffer,0,icmpBuffer.Length,null);
                    MoreAssert.AreSequenceEqual(illegalPacket.Ethernet.Ip.Icmp.ToArray(),
                                    icmpBuffer);

                    Assert.Equal(illegalPacket,
                                    PacketBuilder.Build(DateTime.Now, ethernetLayer, ipLayer, illegalPacket.Ethernet.Ip.Icmp.ExtractLayer()));
                }

                // Ethernet
                ethernetLayer.EtherType = ipLayer == ipV4Layer ? EthernetType.IpV4 : EthernetType.IpV6;
                Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());
                ethernetLayer.EtherType = EthernetType.None;

                // IP.
                if (ipLayer == ipV4Layer)
                {
                    // IPv4.
                    ipV4Layer.Protocol = IpV4Protocol.InternetControlMessageProtocol;
                    ipV4Layer.HeaderChecksum = ((IpV4Layer)packet.Ethernet.IpV4.ExtractLayer()).HeaderChecksum;
                    Assert.Equal(ipV4Layer, packet.Ethernet.IpV4.ExtractLayer());
                    ipV4Layer.HeaderChecksum = null;
                    Assert.Equal(ipV4Layer.Length, packet.Ethernet.IpV4.HeaderLength);
                    Assert.True(packet.Ethernet.IpV4.IsHeaderChecksumCorrect);
                    Assert.Equal(ipV4Layer.Length + icmpLayer.Length + icmpPayloadLength,
                                    packet.Ethernet.IpV4.TotalLength);
                    Assert.Equal(IpV4Datagram.DefaultVersion, packet.Ethernet.IpV4.Version);
                } 
                else
                {
                    // IPv6.
                    Assert.Equal(ipLayer, packet.Ethernet.IpV6.ExtractLayer());
                }

                // ICMP
                IcmpDatagram actualIcmp = packet.Ethernet.Ip.Icmp;
                IcmpLayer actualIcmpLayer = (IcmpLayer)actualIcmp.ExtractLayer();
                icmpLayer.Checksum = actualIcmpLayer.Checksum;
                Assert.Equal(icmpLayer, actualIcmpLayer);
                Assert.Equal(icmpLayer.GetHashCode(), actualIcmpLayer.GetHashCode());
                if (actualIcmpLayer.MessageType != IcmpMessageType.RouterSolicitation)
                {
                    Assert.NotEqual(random.NextIcmpLayer(), actualIcmpLayer);
                    IcmpLayer otherIcmpLayer = random.NextIcmpLayer();
                    Assert.NotEqual(otherIcmpLayer.GetHashCode(), actualIcmpLayer.GetHashCode());
                }
                Assert.True(actualIcmp.IsChecksumCorrect);
                Assert.Equal(icmpLayer.MessageType, actualIcmp.MessageType);
                Assert.Equal(icmpLayer.CodeValue, actualIcmp.Code);
                Assert.Equal(icmpLayer.MessageTypeAndCode, actualIcmp.MessageTypeAndCode);
                Assert.Equal(packet.Length - ethernetLayer.Length - ipLayer.Length - IcmpDatagram.HeaderLength, actualIcmp.Payload.Length);
                Assert.NotNull(icmpLayer.ToString());

                switch (packet.Ethernet.Ip.Icmp.MessageType)
                {
                    case IcmpMessageType.RouterSolicitation:
                    case IcmpMessageType.SourceQuench:
                    case IcmpMessageType.TimeExceeded:
                        Assert.Equal<uint>(0, actualIcmp.Variable);
                        break;

                    case IcmpMessageType.DestinationUnreachable:
                    case IcmpMessageType.ParameterProblem:
                    case IcmpMessageType.Redirect:
                    case IcmpMessageType.ConversionFailed:
                    case IcmpMessageType.Echo:
                    case IcmpMessageType.EchoReply:
                    case IcmpMessageType.Timestamp:
                    case IcmpMessageType.TimestampReply:
                    case IcmpMessageType.InformationRequest:
                    case IcmpMessageType.InformationReply:
                    case IcmpMessageType.RouterAdvertisement:
                    case IcmpMessageType.AddressMaskRequest:
                    case IcmpMessageType.AddressMaskReply:
                        break;
                    case IcmpMessageType.TraceRoute:
                        Assert.Equal(((IcmpTraceRouteLayer)icmpLayer).ReturnHopCount == 0xFFFF, ((IcmpTraceRouteDatagram)actualIcmp).IsOutbound);
                        break;
                    case IcmpMessageType.DomainNameRequest:
                    case IcmpMessageType.SecurityFailures:
                        break;

                    case IcmpMessageType.DomainNameReply:
                    default:
                        throw new InvalidOperationException("Invalid icmpMessageType " + packet.Ethernet.Ip.Icmp.MessageType);

                }
            }
        }

        [Fact]
        public void IcmpRouterAdvertisementEntryTest()
        {
            Random random = new Random();
            IcmpRouterAdvertisementEntry entry1 = new IcmpRouterAdvertisementEntry(random.NextIpV4Address(), random.Next());
            IcmpRouterAdvertisementEntry entry2 = new IcmpRouterAdvertisementEntry(random.NextIpV4Address(), random.Next());

            Assert.Equal(entry1, entry1);
            Assert.Equal(entry1.GetHashCode(), entry1.GetHashCode());
            Assert.NotEqual(entry1, entry2);
            Assert.NotEqual(entry1.GetHashCode(), entry2.GetHashCode());
        }

        [Fact]
        public void IcmpDatagramCreateDatagramNullBufferTest()
        {
            Assert.Throws<ArgumentNullException>(() => IcmpDatagram.CreateDatagram(null, 0, 0));
        }

        [Fact]
        public void IcmpDatagramCreateDatagramBadOffsetTest()
        {
            Assert.IsType<IcmpUnknownDatagram>(IcmpDatagram.CreateDatagram(new byte[0], -1, 0));
        }

        [Fact]
        public void IcmpParameterProblemLayerOriginalDatagramLengthNotRound()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IcmpParameterProblemLayer {OriginalDatagramLength = 6});
        }

        [Fact]
        public void IcmpParameterProblemLayerOriginalDatagramLengthTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IcmpParameterProblemLayer { OriginalDatagramLength = 2000 });
        }
    }
}