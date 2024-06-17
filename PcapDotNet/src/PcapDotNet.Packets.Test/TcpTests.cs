using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
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
    /// Summary description for TcpTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class TcpTests
    {
        [Fact]
        public void RandomTcpTest()
        {
            MacAddress ethernetSource = new MacAddress("00:01:02:03:04:05");
            MacAddress ethernetDestination = new MacAddress("A0:A1:A2:A3:A4:A5");

            EthernetLayer ethernetLayer = new EthernetLayer
                                              {
                                                  Source = ethernetSource,
                                                  Destination = ethernetDestination
                                              };

            int seed = new Random().Next();
            Console.WriteLine("Seed: " + seed);
            Random random = new Random(seed);

            for (int i = 0; i != 1000; ++i)
            {
                IpV4Layer ipV4Layer = random.NextIpV4Layer(null);
                ipV4Layer.HeaderChecksum = null;
                IpV6Layer ipV6Layer = random.NextIpV6Layer(IpV4Protocol.Tcp, false);

                EthernetType ethernetType = random.NextBool() ? EthernetType.IpV4 : EthernetType.IpV6;
                Layer ipLayer = (ethernetType == EthernetType.IpV4 ? (Layer)ipV4Layer : ipV6Layer);
                TcpLayer tcpLayer = random.NextTcpLayer();

                PayloadLayer payloadLayer = random.NextPayloadLayer(random.Next(60000));

                Packet packet = PacketBuilder.Build(DateTime.Now, ethernetLayer, ipLayer, tcpLayer, payloadLayer);

                Assert.True(packet.IsValid);

                // Ethernet
                ethernetLayer.EtherType = ethernetType;
                Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());
                ethernetLayer.EtherType = EthernetType.None;

                // Ip.
                if (ipLayer == ipV4Layer)
                {
                    // IpV4.
                    ipV4Layer.Protocol = IpV4Protocol.Tcp;
                    ipV4Layer.HeaderChecksum = ((IpV4Layer)packet.Ethernet.IpV4.ExtractLayer()).HeaderChecksum;
                    Assert.Equal(ipV4Layer, packet.Ethernet.IpV4.ExtractLayer());
                    ipV4Layer.HeaderChecksum = null;
                } 
                else
                {
                    Assert.Equal(ipV6Layer, packet.Ethernet.IpV6.ExtractLayer());
                }

                // TCP
                tcpLayer.Checksum = packet.Ethernet.Ip.Tcp.Checksum;
                Assert.Equal(tcpLayer, packet.Ethernet.Ip.Tcp.ExtractLayer());
                Assert.NotEqual(random.NextTcpLayer(), packet.Ethernet.Ip.Tcp.ExtractLayer());
                Assert.Equal(tcpLayer.GetHashCode(), packet.Ethernet.Ip.Tcp.ExtractLayer().GetHashCode());
                Assert.NotEqual(random.NextTcpLayer().GetHashCode(), packet.Ethernet.Ip.Tcp.ExtractLayer().GetHashCode());
                Assert.Equal((uint)(packet.Ethernet.Ip.Tcp.SequenceNumber + packet.Ethernet.Ip.Tcp.PayloadLength), packet.Ethernet.Ip.Tcp.NextSequenceNumber);
                foreach (TcpOption option in packet.Ethernet.Ip.Tcp.Options.OptionsCollection)
                {
                    Assert.Equal(option, option);
                    Assert.Equal(option.GetHashCode(), option.GetHashCode());
                    Assert.False(string.IsNullOrEmpty(option.ToString()));
                    Assert.False(option.Equals(null));
                    Assert.False(option.Equals(2));
                }
                Assert.Equal(tcpLayer.Options, packet.Ethernet.Ip.Tcp.Options);
                Assert.Equal((tcpLayer.ControlBits & TcpControlBits.Acknowledgment) == TcpControlBits.Acknowledgment, packet.Ethernet.Ip.Tcp.IsAcknowledgment);
                Assert.Equal((tcpLayer.ControlBits & TcpControlBits.CongestionWindowReduced) == TcpControlBits.CongestionWindowReduced, packet.Ethernet.Ip.Tcp.IsCongestionWindowReduced);
                Assert.Equal((tcpLayer.ControlBits & TcpControlBits.ExplicitCongestionNotificationEcho) == TcpControlBits.ExplicitCongestionNotificationEcho, packet.Ethernet.Ip.Tcp.IsExplicitCongestionNotificationEcho);
                Assert.Equal((tcpLayer.ControlBits & TcpControlBits.Fin) == TcpControlBits.Fin, packet.Ethernet.Ip.Tcp.IsFin);
                Assert.Equal((tcpLayer.ControlBits & TcpControlBits.Push) == TcpControlBits.Push, packet.Ethernet.Ip.Tcp.IsPush);
                Assert.Equal((tcpLayer.ControlBits & TcpControlBits.Reset) == TcpControlBits.Reset, packet.Ethernet.Ip.Tcp.IsReset);
                Assert.Equal((tcpLayer.ControlBits & TcpControlBits.Synchronize) == TcpControlBits.Synchronize, packet.Ethernet.Ip.Tcp.IsSynchronize);
                Assert.Equal((tcpLayer.ControlBits & TcpControlBits.Urgent) == TcpControlBits.Urgent, packet.Ethernet.Ip.Tcp.IsUrgent);
                Assert.Equal(0, packet.Ethernet.Ip.Tcp.Reserved);
                Assert.False(packet.Ethernet.Ip.Tcp.IsChecksumOptional, "IsChecksumOptional");
                Assert.Equal(TcpDatagram.HeaderMinimumLength + tcpLayer.Options.BytesLength + payloadLayer.Length, packet.Ethernet.Ip.Tcp.Length);
                Assert.True(packet.Ethernet.Ip.IsTransportChecksumCorrect, "IsTransportChecksumCorrect");

                Assert.Equal(payloadLayer.Data, packet.Ethernet.Ip.Tcp.Payload);
            }
        }

        [Fact]
        public void TcpTooShort()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(), new TcpLayer());
            Assert.True(packet.IsValid);
            Assert.NotNull(packet.Ethernet.IpV4.Tcp.Payload);
            packet = new Packet(packet.Take(packet.Length - 1).ToArray(), DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(packet.IsValid);
            Assert.Null(packet.Ethernet.IpV4.Tcp.Payload);
        }
        
        [Fact]
        public void TcpOptionSelectiveAcknowledgmentBlockTest()
        {
            TcpOptionSelectiveAcknowledgmentBlock block1 = new TcpOptionSelectiveAcknowledgmentBlock();
            Assert.Equal<uint>(0, block1.LeftEdge);
            Assert.Equal<uint>(0, block1.RightEdge);

            block1 = new TcpOptionSelectiveAcknowledgmentBlock(1, 2);
            Assert.Equal<uint>(1, block1.LeftEdge);
            Assert.Equal<uint>(2, block1.RightEdge);

            TcpOptionSelectiveAcknowledgmentBlock block2 = new TcpOptionSelectiveAcknowledgmentBlock();
            Assert.NotEqual(block1, block2);
            Assert.True(block1 != block2);
            Assert.False(block1 == block2);
            Assert.NotEqual(block1.ToString(), block2.ToString());

            block2 = new TcpOptionSelectiveAcknowledgmentBlock(1, 2);
            Assert.Equal(block1, block2);
            Assert.False(block1 != block2);
            Assert.True(block1 == block2);
        }

        [Fact]
        public void TcpOptionMd5SignatureConstructorErrorDataLengthTest()
        {
            Assert.Throws<ArgumentException>(() => new TcpOptionMd5Signature(new byte[10]));
        }

        [Fact]
        public void TcpOptionMd5SignatureCreateInstanceErrorDataLengthTest()
        {
            Packet packet =
                PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV4Layer(),
                                     new TcpLayer
                                         {
                                             Options =
                                                 new TcpOptions(
                                                 new TcpOptionMd5Signature(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
                                         });

            Assert.True(packet.IsValid);
            Assert.True(packet.Ethernet.IpV4.Tcp.Options.IsValid);

            byte[] buffer = packet.Buffer;
            buffer[buffer.Length - packet.Ethernet.IpV4.Tcp.Length + TcpDatagram.HeaderMinimumLength + 1] = 2;
            packet = new Packet(buffer, packet.Timestamp, packet.DataLink);

            Assert.False(packet.Ethernet.IpV4.Tcp.Options.IsValid);
        }

        [Fact]
        public void TcpOptionMd5SignatureConstructorNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => new TcpOptionMd5Signature(null));
        }

        [Fact]
        public void TcpOptionMoodConstructorBadEmotionStringTest()
        {
            Assert.Throws<InvalidOperationException>(() => new TcpOptionMood((TcpOptionMoodEmotion)202).EmotionString);
        }

        [Fact]
        public void TcpOptionMoodReadFromBufferBadEmotionStringTest()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now,
                                                new IpV4Layer(),
                                                new TcpLayer
                                                {
                                                    Options = new TcpOptions(new TcpOptionMood(TcpOptionMoodEmotion.Happy))
                                                });
            Assert.True(packet.IsValid);
            Assert.Equal(1, packet.IpV4.Tcp.Options.Count);

            byte[] newPacketBuffer = new byte[packet.Length];
            packet.CopyTo(newPacketBuffer, 0);
            newPacketBuffer[packet.Length - 1] = (byte)'a';
            newPacketBuffer[packet.Length - 2] = (byte)'a';
            Packet newPacket = new Packet(newPacketBuffer, DateTime.Now, DataLinkKind.IpV4);

            Assert.False(newPacket.IsValid);
            Assert.Equal(0, newPacket.IpV4.Tcp.Options.Count);
        }

        [Fact]
        public void TcpChecksumTest()
        {
            Packet packet = Packet.FromHexadecimalString(
                "72ad58bae3b13638b5e35a3f08004a6c0055fd5400000e0622f341975faa3bfb25ed83130cb2e02103adfc7efbac1c2bb0f402e64800bb641bc8de8fa185e8ff716b60faf864bfe85901040205021ceec26d916419de400347f33fcca9ad44e9ffae8f",
                DateTime.Now, DataLinkKind.Ethernet);

            Assert.False(packet.Ethernet.IpV4.IsTransportChecksumCorrect);
        }
    }
}