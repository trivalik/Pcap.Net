using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using PcapDotNet.Base;
using PcapDotNet.Core.Extensions;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.TestUtils;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for LivePacketDeviceTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class LivePacketDeviceTests
    {
        [Fact]
        public void SendAndReceievePacketTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";
            const int NumPacketsToSend = 10;

            using (PacketCommunicator communicator = OpenLiveDevice(100))
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet packet;
                DateTime startWaiting = DateTime.Now;
                PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                DateTime finishedWaiting = DateTime.Now;

                Assert.Equal(PacketCommunicatorReceiveResult.Timeout, result);
                Assert.Equal<uint>(0, communicator.TotalStatistics.PacketsCaptured);
                MoreAssert.IsInRange(TimeSpan.FromSeconds(0.99), TimeSpan.FromSeconds(1.075), finishedWaiting - startWaiting);

                Packet sentPacket = _random.NextEthernetPacket(200, 300, SourceMac, DestinationMac);

                DateTime startSendingTime = DateTime.Now;

                for (int i = 0; i != NumPacketsToSend; ++i)
                {
                    communicator.SendPacket(sentPacket);
                }

                DateTime endSendingTime = DateTime.Now;

                for (int i = 0; i != NumPacketsToSend; ++i)
                {
                    result = communicator.ReceivePacket(out packet);

                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(100, packet.Length);
                    Assert.Equal<uint>(200, packet.OriginalLength);
                    MoreAssert.IsInRange(startSendingTime - TimeSpan.FromSeconds(1), endSendingTime + TimeSpan.FromSeconds(30), packet.Timestamp);
                }
                Assert.Equal<uint>(NumPacketsToSend, communicator.TotalStatistics.PacketsCaptured);
            }
        }

        [Fact]
        public void SendNullPacketTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentNullException>(() => communicator.SendPacket(null));
            }
        }

        [Fact]
        public void SetNullFilterTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentNullException>(() => communicator.SetFilter(null as BerkeleyPacketFilter));
            }
        }

        [Fact]
        public void SetNullSamplingMethodTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentNullException>(() => communicator.SetSamplingMethod(null));
            }
        }

        [Fact]
        public void ReceiveSomePacketsTest()
        {
            const int NumPacketsToSend = 100;
            const int PacketSize = 100;

            // Test normal mode
            TestReceiveSomePackets(0, 0, int.MaxValue, PacketSize, false, PacketCommunicatorReceiveResult.Ok, 0, 1, 1.06);
            TestReceiveSomePackets(NumPacketsToSend, NumPacketsToSend, int.MaxValue, PacketSize, false, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend, 0, 0.02);
            TestReceiveSomePackets(NumPacketsToSend, 0, int.MaxValue, PacketSize, false, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend, 0, 0.02);
            TestReceiveSomePackets(NumPacketsToSend, -1, int.MaxValue, PacketSize, false, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend, 0, 0.028);
            TestReceiveSomePackets(NumPacketsToSend, NumPacketsToSend + 1, int.MaxValue, PacketSize, false, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend, 0, 0.031);

            // Test non blocking
            TestReceiveSomePackets(0, 0, int.MaxValue, PacketSize, true, PacketCommunicatorReceiveResult.Ok, 0, 0, 0.02);
            TestReceiveSomePackets(NumPacketsToSend, NumPacketsToSend, int.MaxValue, PacketSize, true, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend, 0, 0.02);

            // Test break loop
            TestReceiveSomePackets(NumPacketsToSend, NumPacketsToSend, NumPacketsToSend / 2, PacketSize, false, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend / 2, 0, 0.02);
            TestReceiveSomePackets(NumPacketsToSend, NumPacketsToSend, NumPacketsToSend / 2, PacketSize, true, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend / 2, 0, 0.02);
            TestReceiveSomePackets(NumPacketsToSend, NumPacketsToSend, 0, PacketSize, false, PacketCommunicatorReceiveResult.BreakLoop, 0, 0, 0.02);
        }

        [Fact]
        public void ReceivePacketsTest()
        {        
            const int NumPacketsToSend = 100;
            const int PacketSize = 100;

            // Normal
            TestReceivePackets(NumPacketsToSend, NumPacketsToSend, int.MaxValue, 2, PacketSize, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend, 0, 0.12);

            // Wait for less packets
            TestReceivePackets(NumPacketsToSend, NumPacketsToSend / 2, int.MaxValue, 2, PacketSize, PacketCommunicatorReceiveResult.Ok, NumPacketsToSend / 2, 0, 0.04);

            // Wait for more packets
            TestReceivePackets(NumPacketsToSend, 0, int.MaxValue, 2, PacketSize, PacketCommunicatorReceiveResult.None, NumPacketsToSend, 2, 2.45);
            TestReceivePackets(NumPacketsToSend, -1, int.MaxValue, 2, PacketSize, PacketCommunicatorReceiveResult.None, NumPacketsToSend, 2, 2.3);
            TestReceivePackets(NumPacketsToSend, NumPacketsToSend + 1, int.MaxValue, 2, PacketSize, PacketCommunicatorReceiveResult.None, NumPacketsToSend, 2, 2.16);

            // Break loop
            TestReceivePackets(NumPacketsToSend, NumPacketsToSend, 0, 2, PacketSize, PacketCommunicatorReceiveResult.BreakLoop, 0, 0, 0.027);
            TestReceivePackets(NumPacketsToSend, NumPacketsToSend, NumPacketsToSend / 2, 2, PacketSize, PacketCommunicatorReceiveResult.BreakLoop, NumPacketsToSend / 2, 0, 0.046);
        }

        [Fact]
        public void ReceivePacketsEnumerableTest()
        {
            const int NumPacketsToSend = 100;
            const int PacketSize = 100;

            // Normal
            TestReceivePacketsEnumerable(NumPacketsToSend, NumPacketsToSend, int.MaxValue, 2, PacketSize, NumPacketsToSend, 0, 0.3);

            // Wait for less packets
            TestReceivePacketsEnumerable(NumPacketsToSend, NumPacketsToSend / 2, int.MaxValue, 2, PacketSize, NumPacketsToSend / 2, 0, 0.032);

            // Wait for more packets
            TestReceivePacketsEnumerable(NumPacketsToSend, -1, int.MaxValue, 2, PacketSize, NumPacketsToSend, 2, 2.14);
            TestReceivePacketsEnumerable(NumPacketsToSend, NumPacketsToSend + 1, int.MaxValue, 2, PacketSize, NumPacketsToSend, 2, 2.13);

            // Break loop
            TestReceivePacketsEnumerable(NumPacketsToSend, NumPacketsToSend, 0, 2, PacketSize, 0, 0, 0.051);
            TestReceivePacketsEnumerable(NumPacketsToSend, NumPacketsToSend, NumPacketsToSend / 2, 2, PacketSize, NumPacketsToSend / 2, 0, 0.1);
        }

        [Fact]
        public void ReceivePacketsGcCollectTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            const int NumPackets = 2;

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);

                for (int i = 0; i != NumPackets; ++i)
                {
                    communicator.SendPacket(sentPacket);
                }

                PacketCommunicatorReceiveResult result = communicator.ReceivePackets(NumPackets, delegate
                                                                                                 {
                                                                                                     GC.Collect();
                                                                                                 });
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
            }
        }

        [Fact]
        public void ReceiveSomePacketsGcCollectTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            const int NumPackets = 2;

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);

                for (int i = 0; i != NumPackets; ++i)
                    communicator.SendPacket(sentPacket);

                int numGot;
                PacketCommunicatorReceiveResult result = communicator.ReceiveSomePackets(out numGot, NumPackets,
                                                                                         delegate 
                                                                                         {
                                                                                             GC.Collect();
                                                                                         });
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                Assert.Equal(NumPackets, numGot);
            }
        }

        [Fact]
        public void ReceiveStatisticsGcCollectTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            const int NumStatistics = 2;

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.Mode = PacketCommunicatorMode.Statistics;

                PacketCommunicatorReceiveResult result = communicator.ReceiveStatistics(NumStatistics, delegate
                                                                                                       {
                                                                                                           GC.Collect();
                                                                                                       });
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
            }
        }

        [Fact]
        public void ReceiveStatisticsTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";
            const int NumPacketsToSend = 100;
            const int PacketSize = 100;

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(PacketSize, SourceMac, DestinationMac);

                PacketSampleStatistics statistics;
                PacketCommunicatorReceiveResult result = communicator.ReceiveStatistics(out statistics);
                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                MoreAssert.IsInRange(DateTime.Now.AddSeconds(-1), DateTime.Now.AddSeconds(1), statistics.Timestamp);
                Assert.Equal<ulong>(0, statistics.AcceptedPackets);
                Assert.Equal<ulong>(0, statistics.AcceptedBytes);

                for (int i = 0; i != NumPacketsToSend; ++i)
                    communicator.SendPacket(sentPacket);

                result = communicator.ReceiveStatistics(out statistics);

                Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                MoreAssert.IsInRange(DateTime.Now.AddSeconds(-1), DateTime.Now.AddSeconds(1), statistics.Timestamp);
                Assert.Equal<ulong>(NumPacketsToSend, statistics.AcceptedPackets);
                // Todo check byte statistics. See http://www.winpcap.org/pipermail/winpcap-users/2015-February/004931.html
//                Assert.AreEqual<long>((sentPacket.Length * NumPacketsToSend), statistics.AcceptedBytes,
//                                      "AcceptedBytes. Diff Per Packet: " +
//                                      (statistics.AcceptedBytes - sentPacket.Length * NumPacketsToSend) /
//                                      ((double)NumPacketsToSend));
            }
        }

        [Fact]
        public void GetStatisticsTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";
            const int NumPacketsToSend = 100;
            const int NumStatisticsToGather = 3;
            const int PacketSize = 100;

            // Normal
            TestGetStatistics(SourceMac, DestinationMac, NumPacketsToSend, NumStatisticsToGather, int.MaxValue, 5, PacketSize,
                              PacketCommunicatorReceiveResult.Ok, NumStatisticsToGather, NumPacketsToSend, NumStatisticsToGather, NumStatisticsToGather + 0.16);

            // Wait for less statistics
            TestGetStatistics(SourceMac, DestinationMac, NumPacketsToSend, NumStatisticsToGather / 2, int.MaxValue, 5, PacketSize,
                              PacketCommunicatorReceiveResult.Ok, NumStatisticsToGather / 2, NumPacketsToSend, NumStatisticsToGather / 2, NumStatisticsToGather / 2 + 0.17);

            // Wait for more statistics
            TestGetStatistics(SourceMac, DestinationMac, NumPacketsToSend, 0, int.MaxValue, 5.5, PacketSize,
                              PacketCommunicatorReceiveResult.None, 5, NumPacketsToSend, 5.5, 5.85);

            // Break loop
            TestGetStatistics(SourceMac, DestinationMac, NumPacketsToSend, NumStatisticsToGather, 0, 5, PacketSize,
                              PacketCommunicatorReceiveResult.BreakLoop, 0, 0, 0, 0.04);
            TestGetStatistics(SourceMac, DestinationMac, NumPacketsToSend, NumStatisticsToGather, NumStatisticsToGather / 2, 5, PacketSize,
                              PacketCommunicatorReceiveResult.BreakLoop, NumStatisticsToGather / 2, NumPacketsToSend, NumStatisticsToGather / 2, NumStatisticsToGather / 2 + 0.22);
        }

        [Fact]
        public void GetStatisticsOnCaptureModeErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                PacketSampleStatistics statistics;
                Assert.Throws<InvalidOperationException>(() => communicator.ReceiveStatistics(out statistics));
            }
        }

        [Fact]
        public void GetPacketOnStatisticsModeErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;
                Packet packet;
                Assert.Throws<InvalidOperationException>(() => communicator.ReceivePacket(out packet));
            }
        }

        [Fact]
        public void SetInvalidModeErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.Mode = (PacketCommunicatorMode)(-99));
            }
        }

        // this test is removed for now since it doens't throw an exception for such big value
        //        [Fact]
        //        public void SetBigKernelBufferSizeErrorTest()
        //        {
        //            using (PacketCommunicator communicator = OpenLiveDevice())
        //            {
        //                Assert.Throws<InvalidOperationException>(() => communicator.SetKernelBufferSize(1024 * 1024 * 1024));
        //            }
        //        }

        [Fact]
        public void SetSmallKernelBufferSizeGetPacketErrorTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelBufferSize(10);
                Packet packet = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                communicator.SendPacket(packet);
                Assert.Throws<InvalidOperationException>(() => communicator.ReceivePacket(out packet));
            }
        }

        [Fact]
        public void SetSmallKernelBufferSizeGetSomePacketsErrorTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelBufferSize(10);
                Packet packet = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                communicator.SendPacket(packet);
                int numPacketsGot;
                Assert.Throws<InvalidOperationException>(() => communicator.ReceiveSomePackets(out numPacketsGot, 1, delegate { }));
            }
        }

        [Fact]
        public void SetSmallKernelBufferSizeGetPacketsErrorTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelBufferSize(10);
                Packet packet = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                communicator.SendPacket(packet);
                Exception exception = null;
                Thread thread = new Thread(delegate()
                                           {
                                               try
                                               {
                                                   communicator.ReceivePackets(1, delegate { });
                                               }
                                               catch (Exception e)
                                               {
                                                   exception = e;
                                               }
                                           });
                thread.Start();
                if (!thread.Join(TimeSpan.FromSeconds(5)))
                    thread.Abort();

                Assert.IsType<InvalidOperationException>(exception);
            }

            Assert.Fail();
        }

        [Fact]
        public void SetSmallKernelBufferSizeGetNextStatisticsErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;
                communicator.SetKernelBufferSize(10);
                PacketSampleStatistics statistics;
                Assert.Throws<InvalidOperationException>(() => communicator.ReceiveStatistics(out statistics));
            }
        }

        [Fact]
        public void SetSmallKernelBufferSizeGetStatisticsErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;
                communicator.SetKernelBufferSize(10);
                Assert.Throws<InvalidOperationException>(() => communicator.ReceiveStatistics(1, delegate { Assert.Fail(); }));
            }
        }

        [Fact]
        public void SetNonBlockTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.False(communicator.NonBlocking);
                communicator.NonBlocking = false;
                Assert.False(communicator.NonBlocking);
                communicator.NonBlocking = true;
                Assert.True(communicator.NonBlocking);
            }
        }

        [Fact]
        public void SetBigKernelMinimumBytesToCopyTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelMinimumBytesToCopy(1024 * 1024);
                Packet expectedPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                for (int i = 0; i != 5; ++i)
                {
                    communicator.SendPacket(expectedPacket);
                    Packet packet;
                    DateTime start = DateTime.Now;
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    DateTime end = DateTime.Now;
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(expectedPacket, packet);
                    MoreAssert.IsBigger(TimeSpan.FromSeconds(0.9), end - start);
                }
            }
        }

        [Fact]
        public void SetSmallKernelMinimumBytesToCopyTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetKernelMinimumBytesToCopy(1);
                Packet expectedPacket = _random.NextEthernetPacket(100, SourceMac, DestinationMac);
                for (int i = 0; i != 100; ++i)
                {
                    communicator.SendPacket(expectedPacket);
                    Packet packet;
                    DateTime start = DateTime.Now;
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                    DateTime end = DateTime.Now;
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(expectedPacket, packet);
                    MoreAssert.IsSmallerOrEqual(TimeSpan.FromSeconds(0.07), end - start);
                }
            }
        }

        [Fact]
        public void SetSamplingMethodOneEveryNTest()
        {
            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);
                communicator.SetSamplingMethod(new SamplingMethodOneEveryCount(5));
                for (int i = 0; i != 20; ++i)
                {
                    Packet expectedPacket = _random.NextEthernetPacket(60 * (i + 1), SourceMac, DestinationMac);
                    communicator.SendPacket(expectedPacket);
                }

                Packet packet;
                PacketCommunicatorReceiveResult result;
                for (int i = 0; i != 4; ++i)
                {
                    result = communicator.ReceivePacket(out packet);
                    Assert.Equal(PacketCommunicatorReceiveResult.Ok, result);
                    Assert.Equal(60 * 5 * (i + 1), packet.Length);
                }
                result = communicator.ReceivePacket(out packet);
                Assert.Equal(PacketCommunicatorReceiveResult.Timeout, result);
                Assert.Null(packet);
            }
        }

        [Fact]
        public void SetSamplingMethodFirstAfterIntervalTest()
        {
            Random random = new Random();

            MacAddress sourceMac = random.NextMacAddress();
            MacAddress destinationMac = random.NextMacAddress();

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + sourceMac + " and ether dst " + destinationMac);
                communicator.SetSamplingMethod(new SamplingMethodFirstAfterInterval(TimeSpan.FromSeconds(1)));
                int numPacketsGot;
                communicator.ReceiveSomePackets(out numPacketsGot, 100, p => { });

                Packet[] packetsToSend = new Packet[11];
                packetsToSend[0] = _random.NextEthernetPacket(60, sourceMac, destinationMac);
                for (int i = 0; i != 10; ++i)
                    packetsToSend[i + 1] = _random.NextEthernetPacket(60 * (i + 2), sourceMac, destinationMac);

                List<Packet> packets = new List<Packet>(6);
                Thread thread = new Thread(() => packets.AddRange(communicator.ReceivePackets(6)));
                thread.Start();

                communicator.SendPacket(packetsToSend[0]);
                Thread.Sleep(TimeSpan.FromSeconds(0.7));
                for (int i = 0; i != 10; ++i)
                {
                    communicator.SendPacket(packetsToSend[i + 1]);
                    Thread.Sleep(TimeSpan.FromSeconds(0.55));
                }

                if (!thread.Join(TimeSpan.FromSeconds(10)))
                    thread.Abort();
                Assert.True(6 == packets.Count, packets.Select(p => (p.Timestamp-packets[0].Timestamp).TotalSeconds + "(" + p.Length + ")").SequenceToString(", "));
                Packet packet;
                for (int i = 0; i != 6; ++i)
                {
                    Assert.True(60 * (i * 2 + 1) == packets[i].Length, i.ToString());
                }
                PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                Assert.Equal(PacketCommunicatorReceiveResult.Timeout, result);
                Assert.Null(packet);
            }
        }

        [Fact]
        public void SetSamplingMethodOneEveryNErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => communicator.SetSamplingMethod(new SamplingMethodOneEveryCount(0)));
            }
        }

        [Fact]
        public void SetSamplingMethodFirstAfterIntervalNegativeMsErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => communicator.SetSamplingMethod(new SamplingMethodFirstAfterInterval(-1)));
            }
        }

        [Fact]
        public void SetSamplingMethodFirstAfterIntervalNegativeTimespanErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => communicator.SetSamplingMethod(new SamplingMethodFirstAfterInterval(TimeSpan.FromSeconds(-1))));
            }
        }

        [Fact]
        public void SetSamplingMethodFirstAfterIntervalBigTimespanErrorTest()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<ArgumentOutOfRangeException>(() => communicator.SetSamplingMethod(new SamplingMethodFirstAfterInterval(TimeSpan.FromDays(25))));
            }
        }

        [Fact]
        public void SetInvalidDataLink()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                Assert.Throws<InvalidOperationException>(() => communicator.DataLink = new PcapDataLink(0));
            }
        }

        [Fact]
        public void SendZeroPacket()
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SendPacket(new Packet(new byte[0], DateTime.Now, DataLinkKind.Ethernet));
            }
        }

        private static void TestGetStatistics(string sourceMac, string destinationMac, int numPacketsToSend, int numStatisticsToGather, int numStatisticsToBreakLoop, double secondsToWait, int packetSize,
                                              PacketCommunicatorReceiveResult expectedResult, int expectedNumStatistics, int expectedNumPackets, double expectedMinSeconds, double expectedMaxSeconds)
        {
            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.Mode = PacketCommunicatorMode.Statistics;

                communicator.SetFilter("ether src " + sourceMac + " and ether dst " + destinationMac);

                Packet sentPacket = _random.NextEthernetPacket(packetSize, sourceMac, destinationMac);

                PacketCommunicatorReceiveResult result = PacketCommunicatorReceiveResult.None;
                int numStatisticsGot = 0;
                ulong totalPackets = 0;
                ulong totalBytes = 0;
                for (int i = 0; i != numPacketsToSend; ++i)
                    communicator.SendPacket(sentPacket);

                if (numStatisticsToBreakLoop == 0)
                    communicator.Break();
                Thread thread = new Thread(delegate()
                {
                    result = communicator.ReceiveStatistics(numStatisticsToGather,
                                                     delegate(PacketSampleStatistics statistics)
                                                     {
                                                         Assert.NotNull(statistics.ToString());
                                                         totalPackets += statistics.AcceptedPackets;
                                                         totalBytes += statistics.AcceptedBytes;
                                                         ++numStatisticsGot;
                                                         if (numStatisticsGot >= numStatisticsToBreakLoop)
                                                             communicator.Break();
                                                     });
                });

                DateTime startWaiting = DateTime.Now;
                thread.Start();

                if (!thread.Join(TimeSpan.FromSeconds(secondsToWait)))
                    thread.Abort();
                DateTime finishedWaiting = DateTime.Now;
                Assert.Equal(expectedResult, result);
                Assert.Equal(expectedNumStatistics, numStatisticsGot);
                Assert.Equal((ulong)expectedNumPackets, totalPackets);
                // Todo check byte statistics. See http://www.winpcap.org/pipermail/winpcap-users/2015-February/004931.html
//                Assert.Equal((ulong)(numPacketsToSend * sentPacket.Length), totalBytes, "NumBytes");
                MoreAssert.IsInRange(expectedMinSeconds, expectedMaxSeconds, (finishedWaiting - startWaiting).TotalSeconds);
            }
        }

        private static void TestReceiveSomePackets(int numPacketsToSend, int numPacketsToGet, int numPacketsToBreakLoop, int packetSize, bool nonBlocking,
                                                   PacketCommunicatorReceiveResult expectedResult, int expectedNumPackets, double expectedMinSeconds, double expectedMaxSeconds)
        {
            string testDescription = "NumPacketsToSend=" + numPacketsToSend + ". NumPacketsToGet=" + numPacketsToGet +
                                     ". NumPacketsToBreakLoop=" + numPacketsToBreakLoop + ". PacketSize=" + packetSize +
                                     ". NonBlocking=" + nonBlocking;

            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            Packet packetToSend = _random.NextEthernetPacket(packetSize, SourceMac, DestinationMac);

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.NonBlocking = nonBlocking;
                Assert.Equal(nonBlocking, communicator.NonBlocking);
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                int numPacketsGot;
                for (int i = 0; i != numPacketsToSend; ++i)
                    communicator.SendPacket(packetToSend);

                if (numPacketsToBreakLoop == 0)
                    communicator.Break();

                PacketHandler handler = new PacketHandler(packetToSend, communicator, numPacketsToBreakLoop);
                DateTime startWaiting = DateTime.Now;
                PacketCommunicatorReceiveResult result = communicator.ReceiveSomePackets(out numPacketsGot, numPacketsToGet,
                                                                                         handler.Handle);
                DateTime finishedWaiting = DateTime.Now;

                Assert.Equal(expectedResult, result);
                Assert.True(expectedNumPackets == numPacketsGot, "NumPacketsGot. Test: " + testDescription);
                Assert.True(expectedNumPackets == handler.NumPacketsHandled, "NumPacketsHandled. Test: " + testDescription);
                MoreAssert.IsInRange(expectedMinSeconds, expectedMaxSeconds, (finishedWaiting - startWaiting).TotalSeconds, testDescription);
            }
        }

        private static void TestReceivePackets(int numPacketsToSend, int numPacketsToWait, int numPacketsToBreakLoop, double secondsToWait, int packetSize,
                                           PacketCommunicatorReceiveResult expectedResult, int expectedNumPackets,
                                           double expectedMinSeconds, double expectedMaxSeconds)
        {
            string testDescription = "NumPacketsToSend=" + numPacketsToSend + ". NumPacketsToWait=" + numPacketsToWait +
                                     ". NumPacketsToBreakLoop=" + numPacketsToBreakLoop + ". SecondsToWait=" +
                                     secondsToWait + ". PacketSize=" + packetSize;


            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(packetSize, SourceMac, DestinationMac);

                PacketCommunicatorReceiveResult result = PacketCommunicatorReceiveResult.None;

                for (int i = 0; i != numPacketsToSend; ++i)
                    communicator.SendPacket(sentPacket);

                PacketHandler handler = new PacketHandler(sentPacket, communicator, numPacketsToBreakLoop);

                Thread thread = new Thread(delegate()
                {
                    if (numPacketsToBreakLoop == 0)
                        communicator.Break();
                    result = communicator.ReceivePackets(numPacketsToWait, handler.Handle);
                });

                DateTime startWaiting = DateTime.Now;
                thread.Start();

                if (!thread.Join(TimeSpan.FromSeconds(secondsToWait)))
                    thread.Abort();
                DateTime finishedWaiting = DateTime.Now;

                Assert.True(expectedResult == result, testDescription);
                Assert.Equal(expectedNumPackets, handler.NumPacketsHandled);
                MoreAssert.IsInRange(expectedMinSeconds, expectedMaxSeconds, (finishedWaiting - startWaiting).TotalSeconds);
            }
        }

        private static void TestReceivePacketsEnumerable(int numPacketsToSend, int numPacketsToWait, int numPacketsToBreakLoop, double secondsToWait,
                                                         int packetSize, int expectedNumPackets, double expectedMinSeconds, double expectedMaxSeconds)
        {
            string testDescription = "NumPacketsToSend=" + numPacketsToSend + ". NumPacketsToWait=" + numPacketsToWait +
                                     ". NumPacketsToBreakLoop=" + numPacketsToBreakLoop + ". SecondsToWait=" +
                                     secondsToWait + ". PacketSize=" + packetSize;


            const string SourceMac = "11:22:33:44:55:66";
            const string DestinationMac = "77:88:99:AA:BB:CC";

            using (PacketCommunicator communicator = OpenLiveDevice())
            {
                communicator.SetFilter("ether src " + SourceMac + " and ether dst " + DestinationMac);

                Packet sentPacket = _random.NextEthernetPacket(packetSize, SourceMac, DestinationMac);

                for (int i = 0; i != numPacketsToSend; ++i)
                    communicator.SendPacket(sentPacket);

                int actualPacketsReceived = 0;
                Thread thread = new Thread(delegate()
                {
                    if (numPacketsToBreakLoop == 0)
                        communicator.Break();
                    IEnumerable<Packet> packets = numPacketsToWait == -1
                                                      ? communicator.ReceivePackets()
                                                      : communicator.ReceivePackets(numPacketsToWait);
                    foreach (Packet packet in packets)
                    {
                        Assert.Equal(sentPacket, packet);
                        ++actualPacketsReceived;
                        if (actualPacketsReceived == numPacketsToBreakLoop)
                            break;
                    }
                });

                DateTime startWaiting = DateTime.Now;
                thread.Start();

                if (!thread.Join(TimeSpan.FromSeconds(secondsToWait)))
                    thread.Abort();
                DateTime finishedWaiting = DateTime.Now;

                Assert.True(expectedNumPackets == actualPacketsReceived, testDescription);
                MoreAssert.IsInRange(expectedMinSeconds, expectedMaxSeconds, (finishedWaiting - startWaiting).TotalSeconds, testDescription);
            }
        }

        public static PacketCommunicator OpenLiveDevice(int snapshotLength)
        {
            NetworkInterface networkInterface =
                NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(
                    ni => !ni.IsReceiveOnly && ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet && ni.OperationalStatus == OperationalStatus.Up);
            LivePacketDevice device = networkInterface.GetLivePacketDevice();
            MoreAssert.IsMatch(@"Network adapter '.*' on local host", device.Description);
            Assert.NotEqual(DeviceAttributes.None, device.Attributes);
            Assert.NotEqual(MacAddress.Zero, device.GetMacAddress());
            Assert.NotEqual(string.Empty, device.GetPnpDeviceId());
            MoreAssert.IsBiggerOrEqual(1, device.Addresses.Count);
            foreach (DeviceAddress address in device.Addresses)
            {
                if (address.Address.Family == SocketAddressFamily.Internet)
                {
                    MoreAssert.IsMatch("Address: " + SocketAddressFamily.Internet + @" [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ " +
                                       "Netmask: " + SocketAddressFamily.Internet + @" 255\.[0-9]+\.[0-9]+\.[0-9]+ " +
                                       "Broadcast: " + SocketAddressFamily.Internet + @" [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",
                                       address.ToString());
                }
                else
                {
                    Assert.Equal(SocketAddressFamily.Internet6, address.Address.Family);
                    MoreAssert.IsMatch("Address: " + SocketAddressFamily.Internet6 + @" (?:[0-9A-F]{4}:){7}[0-9A-F]{4} " +
                                       "Netmask: " + SocketAddressFamily.Internet6 + @" (?:[0-9A-F]{4}:){7}[0-9A-F]{4} " +
                                       "Broadcast: " + SocketAddressFamily.Internet6 + @" (?:[0-9A-F]{4}:){7}[0-9A-F]{4}",
                                       address.ToString());
                }
            }

            PacketCommunicator communicator = device.Open(snapshotLength, PacketDeviceOpenAttributes.Promiscuous, 1000);
            try
            {
                //MoreAssert.AreSequenceEqual(new[] {DataLinkKind.Ethernet, DataLinkKind.Docsis}.Select(kind => new PcapDataLink(kind)), communicator.SupportedDataLinks);
                PacketTotalStatistics totalStatistics = communicator.TotalStatistics;
                Assert.Equal<object>(totalStatistics, totalStatistics);
                Assert.NotNull(totalStatistics);
                Assert.Equal(totalStatistics.GetHashCode(), totalStatistics.GetHashCode());
                Assert.True(totalStatistics.Equals(totalStatistics));
                Assert.False(totalStatistics.Equals(null));
                Assert.NotNull(totalStatistics);
                //MoreAssert.IsSmallerOrEqual<uint>(1, totalStatistics.PacketsCaptured, "PacketsCaptured");
                //Assert.Equal<uint>(0, totalStatistics.PacketsDroppedByDriver);
                //Assert.Equal<uint>(0, totalStatistics.PacketsDroppedByInterface);
                //MoreAssert.IsSmallerOrEqual<uint>(1, totalStatistics.PacketsReceived);
                Assert.NotNull(totalStatistics.ToString());
                communicator.SetKernelBufferSize(2 * 1024 * 1024); // 2 MB instead of 1
                communicator.SetKernelMinimumBytesToCopy(10); // 10 bytes minimum to copy
                communicator.SetSamplingMethod(new SamplingMethodNone());
                Assert.Equal(DataLinkKind.Ethernet, communicator.DataLink.Kind);
                communicator.DataLink = communicator.DataLink;
                Assert.Equal("EN10MB (Ethernet)", communicator.DataLink.ToString());
                Assert.Equal(communicator.DataLink, new PcapDataLink(communicator.DataLink.Name));
                Assert.True(communicator.IsFileSystemByteOrder);
                Assert.Equal(PacketCommunicatorMode.Capture, communicator.Mode);
                Assert.False(communicator.NonBlocking);
                Assert.Equal(snapshotLength, communicator.SnapshotLength);
                return communicator;
            }
            catch (Exception)
            {
                communicator.Dispose();
                throw;
            }
        }

        public static PacketCommunicator OpenLiveDevice()
        {
            return OpenLiveDevice(PacketDevice.DefaultSnapshotLength);
        }

        private static readonly Random _random = new Random();
    }
}