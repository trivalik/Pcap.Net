using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Xunit;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.TestUtils;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for GreTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class GreTests
    {

        [Fact]
        public void RandomGreTest()
        {
            EthernetLayer ethernetLayer = new EthernetLayer
                                              {
                                                  Source = new MacAddress("00:01:02:03:04:05"),
                                                  Destination = new MacAddress("A0:A1:A2:A3:A4:A5")
                                              };

            int seed = new Random().Next();
            Console.WriteLine("Seed: " + seed);
            Random random = new Random(seed);

            for (int i = 0; i != 200; ++i)
            {
                IpV4Layer ipV4Layer = random.NextIpV4Layer(null);
                ipV4Layer.HeaderChecksum = null;
                Layer ipLayer = random.NextBool() ? (Layer)ipV4Layer : random.NextIpV6Layer(IpV4Protocol.Gre, false);

                GreLayer greLayer = random.NextGreLayer();
                PayloadLayer payloadLayer = random.NextPayloadLayer(random.Next(100));

                PacketBuilder packetBuilder = new PacketBuilder(ethernetLayer, ipLayer, greLayer, payloadLayer);

                Packet packet = packetBuilder.Build(DateTime.Now);
                if (greLayer.Checksum == null &&
                    !new[] { EthernetType.IpV4, EthernetType.IpV6, EthernetType.Arp, EthernetType.VLanTaggedFrame }.Contains(packet.Ethernet.Ip.Gre.ProtocolType))
                {
                    Assert.True(packet.IsValid, "IsValid, ProtocolType=" + packet.Ethernet.Ip.Gre.ProtocolType);
                }

                // Ethernet
                ethernetLayer.EtherType = ipLayer == ipV4Layer ? EthernetType.IpV4 : EthernetType.IpV6;
                Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());
                ethernetLayer.EtherType = EthernetType.None;

                // IP.
                if (ipLayer == ipV4Layer)
                {
                    // IPv4.
                    ipV4Layer.Protocol = IpV4Protocol.Gre;
                    ipV4Layer.HeaderChecksum = ((IpV4Layer)packet.Ethernet.Ip.ExtractLayer()).HeaderChecksum;
                    Assert.Equal(ipV4Layer, packet.Ethernet.Ip.ExtractLayer());
                    ipV4Layer.HeaderChecksum = null;
                    Assert.Equal(ipV4Layer.Length, packet.Ethernet.IpV4.HeaderLength);
                    Assert.True(packet.Ethernet.IpV4.IsHeaderChecksumCorrect);
                    Assert.Equal(ipV4Layer.Length + greLayer.Length + payloadLayer.Length,
                                    packet.Ethernet.Ip.TotalLength);
                    Assert.Equal(IpV4Datagram.DefaultVersion, packet.Ethernet.Ip.Version);
                } 
                else
                {
                    // IPv6.
                    Assert.Equal(ipLayer, packet.Ethernet.Ip.ExtractLayer());
                }

                // GRE
                GreDatagram actualGre = packet.Ethernet.Ip.Gre;
                GreLayer actualGreLayer = (GreLayer)actualGre.ExtractLayer();
                if (greLayer.ChecksumPresent && greLayer.Checksum == null)
                {
                    Assert.True(actualGre.IsChecksumCorrect);
                    greLayer.Checksum = actualGre.Checksum;
                }
                Assert.Equal(greLayer, actualGreLayer);
                if (actualGreLayer.Key != null)
                    actualGreLayer.SetKey(actualGreLayer.KeyPayloadLength.Value, actualGreLayer.KeyCallId.Value);
                else
                {
                    Assert.Null(actualGreLayer.KeyPayloadLength);
                    Assert.Null(actualGreLayer.KeyCallId);
                }
                Assert.Equal(greLayer, actualGreLayer);
                if (actualGre.KeyPresent)
                {
                    Assert.Equal(greLayer.KeyPayloadLength, actualGre.KeyPayloadLength);
                    Assert.Equal(greLayer.KeyCallId, actualGre.KeyCallId);
                }
                Assert.NotEqual(random.NextGreLayer(), actualGreLayer);
                Assert.Equal(greLayer.Length, actualGre.HeaderLength);
                Assert.True(actualGre.KeyPresent ^ (greLayer.Key == null));
                MoreAssert.IsSmaller(8, actualGre.RecursionControl);
                MoreAssert.IsSmaller(32, actualGre.FutureUseBits);
                Assert.True(actualGre.RoutingPresent ^ (greLayer.Routing == null && greLayer.RoutingOffset == null));
                Assert.True(actualGre.SequenceNumberPresent ^ (greLayer.SequenceNumber == null));
                Assert.True(!actualGre.StrictSourceRoute || actualGre.RoutingPresent);
                if (actualGre.RoutingPresent)
                {
                    Assert.NotNull(actualGre.ActiveSourceRouteEntryIndex);
                    if (actualGre.ActiveSourceRouteEntryIndex < actualGre.Routing.Count)
                        Assert.NotNull(actualGre.ActiveSourceRouteEntry);

                    foreach (GreSourceRouteEntry entry in actualGre.Routing)
                    {
                        Assert.Equal(entry.GetHashCode(), entry.GetHashCode());
                        switch (entry.AddressFamily)
                        {
                            case GreSourceRouteEntryAddressFamily.AsSourceRoute:
                                GreSourceRouteEntryAs asEntry = (GreSourceRouteEntryAs)entry;
                                MoreAssert.IsInRange(0, asEntry.AsNumbers.Count, asEntry.NextAsNumberIndex);
                                if (asEntry.NextAsNumberIndex != asEntry.AsNumbers.Count)
                                    Assert.Equal(asEntry.AsNumbers[asEntry.NextAsNumberIndex], asEntry.NextAsNumber);
                                break;

                            case GreSourceRouteEntryAddressFamily.IpSourceRoute:
                                GreSourceRouteEntryIp ipEntry = (GreSourceRouteEntryIp)entry;
                                MoreAssert.IsInRange(0, ipEntry.Addresses.Count, ipEntry.NextAddressIndex);
                                if (ipEntry.NextAddressIndex != ipEntry.Addresses.Count)
                                    Assert.Equal(ipEntry.Addresses[ipEntry.NextAddressIndex], ipEntry.NextAddress);
                                break;

                            default:
                                GreSourceRouteEntryUnknown unknownEntry = (GreSourceRouteEntryUnknown)entry;
                                MoreAssert.IsInRange(0, unknownEntry.Data.Length, unknownEntry.PayloadOffset);
                                break;

                        }
                    }
                }
                else
                {
                    Assert.Null(actualGre.ActiveSourceRouteEntry);
                }

                Assert.NotNull(actualGre.Payload);
                switch (actualGre.ProtocolType)
                {
                    case EthernetType.IpV4:
                        Assert.NotNull(actualGre.IpV4);
                        break;

                    case EthernetType.Arp:
                        Assert.NotNull(actualGre.Arp);
                        break;
                }
            }
        }

        [Fact]
        public void GreAutomaticProtocolType()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new GreLayer(), new IpV4Layer(), new IcmpEchoLayer());
            Assert.True(packet.IsValid);
        }

        [Fact]
        public void GreAutomaticProtocolTypeNoNextLayer()
        {
            Assert.Throws<ArgumentException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new GreLayer()));
        }

        [Fact]
        public void GreAutomaticProtocolTypeBadNextLayer()
        {
            Assert.Throws<ArgumentException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new GreLayer(), new PayloadLayer()));
        }

        [Fact]
        public void InvalidGreTest()
        {
            EthernetLayer ethernetLayer = new EthernetLayer
                                              {
                                                  Source = new MacAddress("00:01:02:03:04:05"),
                                                  Destination = new MacAddress("A0:A1:A2:A3:A4:A5")
                                              };

            int seed = new Random().Next();
            Console.WriteLine("Seed: " + seed);
            Random random = new Random(seed);

            for (int i = 0; i != 100; ++i)
            {
                IpV4Layer ipV4Layer = random.NextIpV4Layer(IpV4Protocol.Gre);
                ipV4Layer.HeaderChecksum = null;
                Layer ipLayer = random.NextBool() ? (Layer)ipV4Layer : random.NextIpV6Layer(IpV4Protocol.Gre, false);

                GreLayer greLayer = random.NextGreLayer();
                greLayer.Checksum = null;
                greLayer.Routing = new List<GreSourceRouteEntry>
                                   {
                                       new GreSourceRouteEntryAs(new List<ushort> {123}.AsReadOnly(), 0),
                                       new GreSourceRouteEntryIp(new List<IpV4Address> {random.NextIpV4Address()}.AsReadOnly(),
                                                                 0)
                                   }.AsReadOnly();

                PacketBuilder packetBuilder = new PacketBuilder(ethernetLayer, ipLayer, greLayer);
                Packet packet = packetBuilder.Build(DateTime.Now);
                Assert.True(packet.IsValid ||
                              new[] { EthernetType.IpV4, EthernetType.IpV6, EthernetType.Arp, EthernetType.VLanTaggedFrame }.Contains(greLayer.ProtocolType),
                              "IsValid. ProtoclType=" + greLayer.ProtocolType);

                GreDatagram gre = packet.Ethernet.Ip.Gre;

                // Remove a byte from routing
                Datagram newIpPayload = new Datagram(gre.Take(gre.Length - 1).ToArray());
                packetBuilder = new PacketBuilder(ethernetLayer, ipLayer, new PayloadLayer {Data = newIpPayload});
                packet = packetBuilder.Build(DateTime.Now);
                Assert.Null(packet.Ethernet.Ip.Gre.Payload);
                Assert.False(packet.IsValid);

                // SreLength is too big
                byte[] buffer = gre.ToArray();
                buffer[buffer.Length - 1] = 200;
                newIpPayload = new Datagram(buffer);
                packetBuilder = new PacketBuilder(ethernetLayer, ipLayer, new PayloadLayer {Data = newIpPayload});
                packet = packetBuilder.Build(DateTime.Now);
                Assert.False(packet.IsValid);

                // PayloadOffset is too big
                buffer = gre.ToArray();
                buffer[gre.Length - 10] = 100;
                newIpPayload = new Datagram(buffer);
                packetBuilder = new PacketBuilder(ethernetLayer, ipLayer, new PayloadLayer {Data = newIpPayload});
                packet = packetBuilder.Build(DateTime.Now);
                Assert.False(packet.IsValid);

                // PayloadOffset isn't aligned to ip
                buffer = gre.ToArray();
                buffer[gre.Length - 10] = 3;
                newIpPayload = new Datagram(buffer);
                packetBuilder = new PacketBuilder(ethernetLayer, ipLayer, new PayloadLayer {Data = newIpPayload});
                packet = packetBuilder.Build(DateTime.Now);
                Assert.False(packet.IsValid);

                // PayloadOffset isn't aligned to as
                buffer = gre.ToArray();
                buffer[gre.Length - 16] = 1;
                newIpPayload = new Datagram(buffer);
                packetBuilder = new PacketBuilder(ethernetLayer, ipLayer, new PayloadLayer {Data = newIpPayload});
                packet = packetBuilder.Build(DateTime.Now);
                Assert.False(packet.IsValid);
            }
        }
    }
}