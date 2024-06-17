using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.Packets.Transport;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for DatagramTests.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class DatagramTests
    {
        [Fact]
        public void RandomDatagramTest()
        {
            Random random = new Random();

            for (int i = 0; i != 1000; ++i)
            {
                Datagram datagram = random.NextDatagram(random.Next(1024));

                Assert.Equal(datagram, new Datagram(new List<byte>(datagram).ToArray()));
                Assert.Equal(datagram.GetHashCode(), new Datagram(new List<byte>(datagram).ToArray()).GetHashCode());

                Assert.NotEqual(datagram, random.NextDatagram(random.Next(10 * 1024)));
                Assert.NotEqual(datagram.GetHashCode(), random.NextDatagram(random.Next(10 * 1024)).GetHashCode());

                if (datagram.Length != 0)
                {
                    Assert.NotEqual(datagram, Datagram.Empty);
                    Assert.NotEqual(datagram, random.NextDatagram(datagram.Length));
                    if (datagram.Length > 2)
                        Assert.NotEqual(datagram.GetHashCode(), random.NextDatagram(datagram.Length).GetHashCode());
                }
                else
                    Assert.Equal(datagram, Datagram.Empty);

                // Check Enumerable
                IEnumerable enumerable = datagram;
                int offset = 0;
                foreach (byte b in enumerable)
                    Assert.Equal(datagram[offset++], b);
            }
        }

        [Fact]
        public void DatagramExtractLayerTest()
        {
            PayloadLayer payloadLayer = new PayloadLayer
                                            {
                                                Data = new Datagram(new byte[] {100, 101, 102})
                                            };

            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer
                                                                  {
                                                                      EtherType = EthernetType.IpV4
                                                                  }, payloadLayer);
            Assert.Equal(payloadLayer, packet.Ethernet.Payload.ExtractLayer());
        }

        [Fact]
        public void DatagramCalculateIsValidTest()
        {
            Datagram data = new Datagram(new byte[]{1,2,3});
            Assert.True(data.IsValid);
        }

        [Fact]
        public void DatagramToMemoryStreamTest()
        {
            Datagram tcpPayload = new Datagram(new byte[] {1, 2, 3});
            Packet packet = PacketBuilder.Build(DateTime.Now,
                                                new EthernetLayer(),
                                                new IpV4Layer(),
                                                new TcpLayer(),
                                                new PayloadLayer {Data = tcpPayload});
            using (MemoryStream stream = packet.Ethernet.IpV4.Tcp.Payload.ToMemoryStream())
            {
                Assert.True(stream.CanRead, "CanRead");
                Assert.True(stream.CanSeek, "CanSeek");
                Assert.False(stream.CanTimeout, "CanTimeout");
                Assert.False(stream.CanWrite, "CanWrite");
                Assert.Equal(tcpPayload.Length, stream.Length);
                for (int i = 0; i != tcpPayload.Length; ++i)
                {
                    Assert.Equal(i, stream.Position);
                    Assert.Equal(i + 1, stream.ReadByte());
                }
            }
        }

        [Fact]
        public void DatagramConstructorNullBufferTest()
        {
            Assert.Throws<ArgumentNullException>(() => new Datagram(null));
        }
    }
}