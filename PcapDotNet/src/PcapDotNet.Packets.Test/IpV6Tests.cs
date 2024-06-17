using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using PcapDotNet.Base;
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
    /// Summary description for IpV6Tests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class IpV6Tests
    {
        // Random tests.

        [Fact]
        public void RandomIpV6Test()
        {
            MacAddress ethernetSource = new MacAddress("00:01:02:03:04:05");
            MacAddress ethernetDestination = new MacAddress("A0:A1:A2:A3:A4:A5");
            const EthernetType EthernetType = EthernetType.IpV6;

            EthernetLayer ethernetLayer = new EthernetLayer
                                              {
                                                  Source = ethernetSource,
                                                  Destination = ethernetDestination,
                                                  EtherType = EthernetType
                                              };

            int seed = new Random().Next();
            Console.WriteLine("Seed: " + seed);
            Random random = new Random(seed);

            for (int i = 0; i != 1000; ++i)
            {
                IpV6Layer ipV6Layer = random.NextIpV6Layer(false);

                PayloadLayer payloadLayer = random.NextPayloadLayer(random.NextInt(0, 50 * 1024));

                List<ILayer> layers = new List<ILayer> {ethernetLayer, ipV6Layer};
                if (ipV6Layer.ExtensionHeaders.LastHeader != IpV4Protocol.EncapsulatingSecurityPayload)
                    layers.Add(payloadLayer);
                Packet packet = PacketBuilder.Build(DateTime.Now, layers);

                Assert.True(ipV6Layer.LastNextHeader == IpV4Protocol.Ip ||
                              ipV6Layer.LastNextHeader == IpV4Protocol.IpV6||
                              ipV6Layer.LastNextHeader == IpV4Protocol.Udp ||
                              ipV6Layer.LastNextHeader == IpV4Protocol.Tcp ||
                              ipV6Layer.LastNextHeader == IpV4Protocol.InternetGroupManagementProtocol ||
                              ipV6Layer.LastNextHeader == IpV4Protocol.InternetControlMessageProtocol ||
                              ipV6Layer.LastNextHeader == IpV4Protocol.Gre ||
                              packet.IsValid, string.Format("IsValid ({0}...{1})", ipV6Layer.NextHeader, ipV6Layer.ExtensionHeaders.NextHeader));

                // Ethernet
                Assert.Equal(packet.Length - EthernetDatagram.HeaderLengthValue, packet.Ethernet.PayloadLength);
                Assert.Equal(ethernetLayer, packet.Ethernet.ExtractLayer());

                // IpV6
                Assert.Equal(ipV6Layer, packet.Ethernet.IpV6.ExtractLayer());
                Assert.Equal(ipV6Layer.GetHashCode(), packet.Ethernet.IpV6.ExtractLayer().GetHashCode());
                Assert.Equal(string.Format("{0} -> {1} ({2})", ipV6Layer.Source, ipV6Layer.CurrentDestination, ipV6Layer.NextHeader), ipV6Layer.ToString());
                IEnumerator extensionHeadersEnumerator = ((IEnumerable)packet.Ethernet.IpV6.ExtensionHeaders).GetEnumerator();
                for (int extensionHeaderIndex = 0; extensionHeaderIndex != packet.Ethernet.IpV6.ExtensionHeaders.Headers.Count; ++extensionHeaderIndex)
                {
                    IpV6ExtensionHeader extensionHeader = packet.Ethernet.IpV6.ExtensionHeaders[extensionHeaderIndex];
                    Assert.True(extensionHeadersEnumerator.MoveNext());
                    Assert.Equal(extensionHeader, extensionHeadersEnumerator.Current);
                    IpV6ExtensionHeader layerExtensionheader = ipV6Layer.ExtensionHeaders[extensionHeaderIndex];
                    Assert.Equal(extensionHeader, layerExtensionheader);
                    Assert.Equal(extensionHeader.GetHashCode(), layerExtensionheader.GetHashCode());
                    IpV6ExtensionHeaderOptions extensionHeaderOptions = extensionHeader as IpV6ExtensionHeaderOptions;
                    if (extensionHeaderOptions != null)
                    {
                        foreach (IpV6Option option in extensionHeaderOptions.Options)
                        {
                            switch (option.OptionType)
                            {
                                case IpV6OptionType.SimplifiedMulticastForwardingDuplicatePacketDetection:
                                    IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetection optionSimplifiedMulticastForwardingDuplicatePacketDetection = (IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetection)option;
                                    Assert.Equal(optionSimplifiedMulticastForwardingDuplicatePacketDetection is IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceHashAssistValue, optionSimplifiedMulticastForwardingDuplicatePacketDetection.HashIndicator);
                                    break;

                                case IpV6OptionType.QuickStart:
                                    IpV6OptionQuickStart optionQuickStart = (IpV6OptionQuickStart)option;
                                    MoreAssert.IsBiggerOrEqual(0, optionQuickStart.RateKbps);
                                    break;
                            }
                        }
                    }
                    IpV6ExtensionHeaderMobility extensionHeaderMobility = extensionHeader as IpV6ExtensionHeaderMobility;
                    if (extensionHeaderMobility != null)
                    {
                        Assert.False(extensionHeaderMobility.Equals(2));
                        Assert.True(extensionHeaderMobility.Equals((object)extensionHeader));
                        Assert.Equal(extensionHeaderMobility.MobilityOptions, new IpV6MobilityOptions(extensionHeaderMobility.MobilityOptions).AsEnumerable());
                        foreach (IpV6MobilityOption option in extensionHeaderMobility.MobilityOptions)
                        {
                            switch (option.OptionType)
                            {
                                case IpV6MobilityOptionType.BindingIdentifier:
                                    IpV6MobilityOptionBindingIdentifier optionBindingIdentifier = (IpV6MobilityOptionBindingIdentifier)option;
                                    if (optionBindingIdentifier.IpV4CareOfAddress.HasValue)
                                        Assert.Equal(optionBindingIdentifier.IpV4CareOfAddress.Value, optionBindingIdentifier.CareOfAddress);
                                    else if (optionBindingIdentifier.IpV6CareOfAddress.HasValue)
                                        Assert.Equal(optionBindingIdentifier.IpV6CareOfAddress.Value, optionBindingIdentifier.CareOfAddress);
                                    else
                                        Assert.Null(optionBindingIdentifier.CareOfAddress);
                                    break;

                                case IpV6MobilityOptionType.AccessNetworkIdentifier:
                                    IpV6MobilityOptionAccessNetworkIdentifier optionAccessNetworkIdentifier = (IpV6MobilityOptionAccessNetworkIdentifier)option;
                                    foreach (IpV6AccessNetworkIdentifierSubOption subOption in optionAccessNetworkIdentifier.SubOptions)
                                    {
                                        switch (subOption.OptionType)
                                        {
                                            case IpV6AccessNetworkIdentifierSubOptionType.GeoLocation:
                                                IpV6AccessNetworkIdentifierSubOptionGeoLocation subOptionGeoLocation =
                                                    (IpV6AccessNetworkIdentifierSubOptionGeoLocation)subOption;
                                                MoreAssert.IsBiggerOrEqual(-90, subOptionGeoLocation.LatitudeDegreesReal);
                                                MoreAssert.IsSmallerOrEqual(90, subOptionGeoLocation.LatitudeDegreesReal);
                                                MoreAssert.IsBiggerOrEqual(-180, subOptionGeoLocation.LongitudeDegreesReal);
                                                MoreAssert.IsSmallerOrEqual(180, subOptionGeoLocation.LongitudeDegreesReal);
                                                IpV6AccessNetworkIdentifierSubOptionGeoLocation subOptionGetLocationFromReal =
                                                    IpV6AccessNetworkIdentifierSubOptionGeoLocation.CreateFromRealValues(
                                                        subOptionGeoLocation.LatitudeDegreesReal,
                                                        subOptionGeoLocation.LongitudeDegreesReal);
                                                Assert.Equal(subOptionGeoLocation, subOptionGetLocationFromReal);
                                                break;
                                        }
                                    }
                                    break;

                                case IpV6MobilityOptionType.Timestamp:
                                    IpV6MobilityOptionTimestamp optionTimestamp = (IpV6MobilityOptionTimestamp)option;
                                    MoreAssert.IsBiggerOrEqual(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), optionTimestamp.TimestampDateTime);
                                    break;

                                case IpV6MobilityOptionType.FlowIdentification:
                                    IpV6MobilityOptionFlowIdentification optionFlowIdentification = (IpV6MobilityOptionFlowIdentification)option;
                                    foreach (IpV6FlowIdentificationSubOption subOption in optionFlowIdentification.SubOptions)
                                    {
                                        switch (subOption.OptionType)
                                        {
                                            case IpV6FlowIdentificationSubOptionType.BindingReference:
                                                IpV6FlowIdentificationSubOptionBindingReference subOptionBindingReference =
                                                    (IpV6FlowIdentificationSubOptionBindingReference)subOption;
                                                Assert.Equal(subOptionBindingReference,
                                                                new IpV6FlowIdentificationSubOptionBindingReference(
                                                                    subOptionBindingReference.BindingIds.AsEnumerable()));
                                                break;
                                        }
                                    }
                                    break;

                                case IpV6MobilityOptionType.CryptographicallyGeneratedAddressParameters:
                                    IpV6MobilityOptionCryptographicallyGeneratedAddressParameters optionCryptographicallyGeneratedAddressParameters = (IpV6MobilityOptionCryptographicallyGeneratedAddressParameters)option;
                                    Assert.Equal(optionCryptographicallyGeneratedAddressParameters.Length - 2, optionCryptographicallyGeneratedAddressParameters.CryptographicallyGeneratedAddressParameters.Length);
                                    break;

                                case IpV6MobilityOptionType.CareOfTest:
                                    Assert.IsType<IpV6MobilityOptionCareOfTest>(option);
                                    break;

                                case IpV6MobilityOptionType.IpV4CareOfAddress:
                                    Assert.IsType<IpV6MobilityOptionIpV4CareOfAddress>(option);
                                    break;

                                case IpV6MobilityOptionType.ReplayProtection:
                                    Assert.IsType<IpV6MobilityOptionReplayProtection>(option);
                                    break;

                                case IpV6MobilityOptionType.Experimental:
                                    IpV6MobilityOptionExperimental optionExperimental = (IpV6MobilityOptionExperimental)option;
                                    Assert.NotNull(optionExperimental.Data);
                                    break;

                                case IpV6MobilityOptionType.PermanentHomeKeygenToken:
                                    IpV6MobilityOptionPermanentHomeKeygenToken optionPermanentHomeKeygenToken =
                                        (IpV6MobilityOptionPermanentHomeKeygenToken)option;
                                    Assert.NotNull(optionPermanentHomeKeygenToken.PermanentHomeKeygenToken);
                                    break;

                                case IpV6MobilityOptionType.Signature:
                                    IpV6MobilityOptionSignature optionSignature = (IpV6MobilityOptionSignature)option;
                                    Assert.NotNull(optionSignature.Signature);
                                    break;
                            }
                        }
                    }
                }
            }
        }

        // IpV6Datagram tests.

        [Fact]
        public void IpV6DatagramParseExtensionHeaderWithShorterThanHeaderLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    NextHeader = IpV4Protocol.Il
                });
            Assert.True(packet.IsValid);
            Packet invalidPacket = new Packet(packet.Buffer.Take(packet.Length - 1).ToArray(), DateTime.Now, DataLinkKind.Ethernet);
            Assert.Equal(IpV6ExtensionHeaders.Empty, invalidPacket.Ethernet.IpV6.ExtensionHeaders);
            Assert.Equal(0, invalidPacket.Ethernet.IpV6.RealPayloadLength);
            Assert.Null(invalidPacket.Ethernet.IpV6.Icmp);
            Assert.False(invalidPacket.IsValid);
        }

        // IpV6Layer tests.

        [Fact]
        public void AutomaticIpV6NextHeader()
        {
            Packet packet = PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV6Layer(), new UdpLayer());
            Assert.Equal(IpV4Protocol.Udp, packet.Ethernet.IpV6.NextHeader);
        }

        [Fact]
        public void AutomaticIpV6NextHeaderNoNextLayer()
        {
            Assert.Throws<InvalidOperationException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV6Layer()));
        }

        [Fact]
        public void AutomaticIpV6NextHeaderUnknownNextLayer()
        {
            Assert.Throws<InvalidOperationException>(() => PacketBuilder.Build(DateTime.Now, new EthernetLayer(), new IpV6Layer(), new PayloadLayer()));
        }

        [Fact]
        public void IpV6LayerWithLayerAfterEncapsulatingSecurityPayload()
        {
            Assert.Throws<ArgumentException>(() =>
                PacketBuilder.Build(
                    DateTime.Now,
                    new EthernetLayer(),
                    new IpV6Layer
                    {
                        ExtensionHeaders = new IpV6ExtensionHeaders(new IpV6ExtensionHeaderEncapsulatingSecurityPayload(0, 0, DataSegment.Empty))
                    },
                    new PayloadLayer { Data = new Datagram(new byte[10]) }));
        }

        // IpV6ExtensionHeader tests.

        [Fact]
        public void IpV6ExtensionHeaderAuthenticationBadPayloadLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderAuthentication(IpV4Protocol.Skip, 0, 0, new DataSegment(new byte[12])))
                });
            Assert.True(packet.IsValid);
            ++packet.Buffer[14 + 40 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6ExtensionHeaderAuthenticationNonIntegralMultipleOf4Bytes()
        {
            Assert.Throws<ArgumentException>(() => new IpV6ExtensionHeaderAuthentication(IpV4Protocol.Skip, 0, 0, new DataSegment(new byte[6])));
        }

        [Fact]
        public void IpV6ExtensionHeaderAuthenticationNullAuthenticationData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6ExtensionHeaderAuthentication(IpV4Protocol.Skip, 0, 0, null));
        }

        [Fact]
        public void IpV6ExtensionHeaderAuthenticationTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderAuthentication(IpV4Protocol.Skip, 0, 0, DataSegment.Empty))
                });
            Assert.True(packet.IsValid);
            Packet invalidPacket = new Packet(packet.Buffer.Take(packet.Length - 1).ToArray(), DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6ExtensionHeaderFragmentDataEquals()
        {
            Assert.NotEqual(new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 0, false, 0),
                               new IpV6ExtensionHeaderFragmentData(IpV4Protocol.SimpleMulticast, 0, false, 0));
            Assert.NotEqual(new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 0, false, 0),
                               new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 1, false, 0));
            Assert.NotEqual(new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 0, false, 0),
                               new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 0, true, 0));
            Assert.NotEqual(new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 0, false, 0),
                               new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 0, false, 1));
        }

        [Fact]
        public void IpV6ExtensionHeaderFragmentDataFragmentOffsetTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 0x2000, false, 0));
        }

        [Fact]
        public void IpV6ExtensionHeaderFragmentDataWrongLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 0, false, 0))
                },
                new PayloadLayer { Data = new Datagram(new byte[100]) });
            Assert.True(packet.IsValid);
            ++packet.Buffer[14 + 40 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6ExtensionHeaderMobilityExperimentalConstructorMessageDataBadLength()
        {
            Assert.Throws<ArgumentException>(() => new IpV6ExtensionHeaderMobilityExperimental(IpV4Protocol.Pin, 0, new DataSegment(new byte[5])));
        }

        [Fact]
        public void IpV6ExtensionHeaderMobilityExperimentalNullMessageData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6ExtensionHeaderMobilityExperimental(IpV4Protocol.Pin, 0, null));
        }
        
        [Fact]
        public void IpV6ExtensionHeaderMobilityHomeAgentSwitchMessageNullHomeAgentAddress()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6ExtensionHeaderMobilityHomeAgentSwitchMessage(IpV4Protocol.IpV6, 0, null, IpV6MobilityOptions.None));
        }

        [Fact]
        public void IpV6ExtensionHeaderRoutingParseDataNimrod()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderRoutingHomeAddress(IpV4Protocol.Skip, 0, IpV6Address.Zero))
                });
            packet.Buffer[14 + 40 + 2] = (byte)IpV6RoutingType.Nimrod;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6ExtensionHeaderRoutingParseDataUnknownRoutingType()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderRoutingHomeAddress(IpV4Protocol.Skip, 0, IpV6Address.Zero))
                });
            packet.Buffer[14 + 40 + 2] = 0x55;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworksCommonPrefixLengthForLastAddressTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworks(IpV4Protocol.Skip, 0, 0, 16, new IpV6Address[0]));
        }

        [Fact]
        public void IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworksCommonPrefixLengthForNonLastAddressesTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworks(IpV4Protocol.Skip, 0, 16, 0, new IpV6Address[0]));
        }

        [Fact]
        public void IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworksCommonPrefixNotCommon()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworks(IpV4Protocol.Skip, 5, 4, 4,
                                                            new IpV6Address("0000:0000:9ABC:DEF0:1234:5678:9ABC:DEF0"),
                                                            new IpV6Address("0000:0001:9ABC:DEF0:1234:5678:9ABC:DEF0")));
        }

        [Fact]
        public void IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworksNullAddresses()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworks(IpV4Protocol.Skip, 0, 15, 0, null));
        }

        [Fact]
        public void IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworksParseRoutingDataPadSizeMakeNumAddressesNegative()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderRoutingProtocolLowPowerAndLossyNetworks(IpV4Protocol.Skip, 8, 8, 0))
                });
            packet.Buffer[14 + 40 + 5] = 0x10;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6ExtensionHeaderTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(IpV4Protocol.Skip, IpV6Options.Empty))
                });
            Assert.True(packet.IsValid);
            Packet invalidPacket = new Packet(packet.Buffer.Take(packet.Length - 1).ToArray(), DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6StandardExtensionHeaderTooShort()
        {
            byte[] payload = new byte[8];
            payload[1] = 10;
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    NextHeader = IpV4Protocol.IpV6Route
                },
                new PayloadLayer { Data = new Datagram(payload) });
            Assert.False(packet.IsValid);
        }

        // IpV6ExtensionHeaders tests.

        [Fact]
        public void IpV6ExtensionHeadersAutomaticNextHeaderByNextExtensionHeader()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(null, IpV6Options.Empty),
                        new IpV6ExtensionHeaderDestinationOptions(IpV4Protocol.Skip, IpV6Options.Empty))
                });

            Assert.True(packet.IsValid);
            Assert.Equal(IpV4Protocol.IpV6Opts, packet.Ethernet.IpV6.ExtensionHeaders[0].NextHeader);
        }

        [Fact]
        public void IpV6ExtensionHeadersAutomaticNextHeaderFailure()
        {
            Assert.Throws<InvalidOperationException>(() => PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(null, IpV6Options.Empty))
                }));
        }

        [Fact]
        public void IpV6ExtensionHeadersConstructors()
        {
            IEnumerable<IpV6ExtensionHeader> extensionHeadersEnumerable = new IpV6ExtensionHeader[0];
            IList<IpV6ExtensionHeader> extensionHeadersIList = new IpV6ExtensionHeader[0];
            Assert.Equal(new IpV6ExtensionHeaders(extensionHeadersEnumerable), new IpV6ExtensionHeaders(extensionHeadersIList));
        }
        
        [Fact]
        public void IpV6ExtensionHeadersEncapsulatingSecurityPayloadBeforeLast()
        {
            Assert.Throws<ArgumentException>(() => new IpV6ExtensionHeaders(new IpV6ExtensionHeaderEncapsulatingSecurityPayload(0, 0, DataSegment.Empty),
                                                   new IpV6ExtensionHeaderFragmentData(IpV4Protocol.Skip, 0, false, 0)));
        }

        [Fact]
        public void IpV6ExtensionHeadersNullReadOnlyCollection()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6ExtensionHeaders(null as ReadOnlyCollection<IpV6ExtensionHeader>));
        }

        // IpV6Option tests.

        [Fact]
        public void IpV6OptionCalipsoChecksum()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Udp,
                            new IpV6Options(new IpV6OptionCalipso(IpV6CalipsoDomainOfInterpretation.Null, 0, null, DataSegment.Empty)))),
                },
                new UdpLayer());
            Assert.True(packet.IsValid);
            Assert.True(((IpV6OptionCalipso)((IpV6ExtensionHeaderDestinationOptions)packet.Ethernet.IpV6.ExtensionHeaders[0]).Options[0]).IsChecksumCorrect);
        }
        
        [Fact]
        public void IpV6OptionCalipsoCompartmentBitmapDoesntDivideBy4()
        {
            Assert.Throws<ArgumentException>(() => new IpV6OptionCalipso(IpV6CalipsoDomainOfInterpretation.Null, 0, null, new DataSegment(new byte[6])));
        }

        [Fact]
        public void IpV6OptionCalipsoCompartmentBitmapTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6OptionCalipso(IpV6CalipsoDomainOfInterpretation.Null, 0, null, new DataSegment(new byte[248])));
        }

        [Fact]
        public void IpV6OptionCalipsoCreateInstanceNullData()
        {
            IpV6OptionCalipso option = new IpV6OptionCalipso(IpV6CalipsoDomainOfInterpretation.Null, 0, null, DataSegment.Empty);
            Assert.Throws<ArgumentNullException>(() => option.CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionCalipsoDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionCalipso(IpV6CalipsoDomainOfInterpretation.Null, 0, null, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionCalipsoDataTooShortForCompartmentBitmap()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionCalipso(IpV6CalipsoDomainOfInterpretation.Null, 0, null, new DataSegment(new byte[8])))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionCalipsoNullCompartmentBitmap()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionCalipso(IpV6CalipsoDomainOfInterpretation.Null, 0, null, null));
        }

        [Fact]
        public void IpV6OptionEndpointIdentificationCreateInstanceNullData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionEndpointIdentification(DataSegment.Empty, DataSegment.Empty).CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionEndpointIdentificationDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionEndpointIdentification(DataSegment.Empty, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionEndpointIdentificationWrongSourceLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionEndpointIdentification(DataSegment.Empty, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            ++packet.Buffer[14 + 40 + 2 + 2];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionHomeAddressCreateInstanceNullData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionHomeAddress(IpV6Address.Zero).CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionHomeAddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionHomeAddress(IpV6Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionJumboPayloadCreateInstanceNullData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionJumboPayload(2000).CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionJumboPayloadDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionJumboPayload(0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionLineIdentificationDestinationCreateInstanceNullLineIdentification()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionLineIdentificationDestination(DataSegment.Empty).CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionLineIdentificationDestinationDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionLineIdentificationDestination(DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionLineIdentificationDestinationLineIdentificationTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6OptionLineIdentificationDestination(new DataSegment(new byte[256])));
        }

        [Fact]
        public void IpV6OptionLineIdentificationDestinationNullLineIdentification()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionLineIdentificationDestination(null));
        }

        [Fact]
        public void IpV6OptionLineIdentificationDestinationWrongLineIdentificationLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionLineIdentificationDestination(DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            ++packet.Buffer[14 + 40 + 2 + 2];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }
        
        [Fact]
        public void IpV6OptionPadNCreateInstanceNullData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionPadN(10).CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionQuickStartCreateInstanceNullData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionQuickStart(IpV4OptionQuickStartFunction.RateRequest, 0, 0, 0).CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionQuickStartDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionQuickStart(IpV4OptionQuickStartFunction.RateRequest, 0, 0, 0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionRouterAlertCreateInstanceNullData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionRouterAlert(IpV6RouterAlertType.Rsvp).CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionRouterAlertDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionRouterAlert(IpV6RouterAlertType.Rsvp))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionRoutingProtocolLowPowerAndLossyNetworksCreateInstanceNullData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionRoutingProtocolLowPowerAndLossyNetworks(false, false, false, 0, 0, DataSegment.Empty).CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionRoutingProtocolLowPowerAndLossyNetworksDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip,
                            new IpV6Options(new IpV6OptionRoutingProtocolLowPowerAndLossyNetworks(false, false, false, 0, 0, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionDefaultNullTaggerId()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionDefault(null, DataSegment.Empty));
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionDefaultTaggerIdTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionDefault(new DataSegment(new byte[17]), DataSegment.Empty));
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionDefaultTaggerIdTooShort()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionDefault(DataSegment.Empty, DataSegment.Empty));
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceBasedDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV4(IpV4Address.Zero, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceBasedEqualsData()
        {
            Assert.Equal(new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV6(IpV6Address.Zero, DataSegment.Empty),
                            new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV6(IpV6Address.Zero, DataSegment.Empty));
            Assert.NotEqual<IpV6OptionComplex>(new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV6(IpV6Address.Zero, DataSegment.Empty),
                               new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV4(IpV4Address.Zero, new DataSegment(new byte[12])));
            Assert.NotEqual<IpV6OptionComplex>(new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV6(IpV6Address.Zero, DataSegment.Empty),
                               new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceHashAssistValue(new DataSegment(new byte[17])));
            Assert.NotEqual<IpV6OptionComplex>(new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionDefault(new DataSegment(new byte[16]), DataSegment.Empty),
                               new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV6(IpV6Address.Zero, DataSegment.Empty));
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceBasedIpV4TaggerIdWrongLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV4(IpV4Address.Zero, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 2 + 2] &= 0xF0;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceBasedIpV6TaggerIdWrongLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV6(IpV6Address.Zero, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 2 + 2] &= 0xF0;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceBasedUnknownTaggerIdType()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionIpV4(IpV4Address.Zero, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 2 + 2] |= 0x70;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceHashAssistValueDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceHashAssistValue(new DataSegment(new byte[1])))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceHashAssistValueNullData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionSimplifiedMulticastForwardingDuplicatePacketDetectionSequenceHashAssistValue(null));
        }

        [Fact]
        public void IpV6OptionTunnelEncapsulationLimitCreateInstanceNullData()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6OptionTunnelEncapsulationLimit(10).CreateInstance(null));
        }

        [Fact]
        public void IpV6OptionTunnelEncapsulationLimitDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionTunnelEncapsulationLimit(0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionUnknown()
        {
            IpV6OptionUnknown option = new IpV6OptionUnknown((IpV6OptionType)0xBB, DataSegment.Empty);
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(IpV4Protocol.Skip, new IpV6Options(option)))
                });
            Assert.True(packet.IsValid);
            IpV6Option actualOption = ((IpV6ExtensionHeaderDestinationOptions)packet.Ethernet.IpV6.ExtensionHeaders[0]).Options[0];
            Assert.Equal(option, actualOption);
            Assert.Equal(option.GetHashCode(), actualOption.GetHashCode());
        }
        
        // IpV6Options tests.

        [Fact]
        public void IpV6OptionsDataTooShortForOptionDataLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionPadN(4))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 3] = 50;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionsDataTooShortForReadingOptionDataLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderDestinationOptions(
                            IpV4Protocol.Skip, new IpV6Options(new IpV6OptionPadN(3), new IpV6OptionPad1())))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 7] = (byte)IpV6OptionType.PadN;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6OptionsEnumerableConstructor()
        {
            IpV6Options options = new IpV6Options(new IpV6Option[] { new IpV6OptionPad1() }.Concat(new IpV6OptionPad1()));
            Assert.Equal(2, options.Count);
            Assert.Equal(new IpV6OptionPad1(), options[0]);
            Assert.Equal(new IpV6OptionPad1(), options[1]);
        }

        // IpV6MobilityOption tests.

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionGeoLocationCreateFromRealValuesLatitudeTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => IpV6AccessNetworkIdentifierSubOptionGeoLocation.CreateFromRealValues(90.1, 0));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionGeoLocationCreateFromRealValuesLatitudeTooSmall()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => IpV6AccessNetworkIdentifierSubOptionGeoLocation.CreateFromRealValues(-90.1, 0));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionGeoLocationCreateFromRealValuesLongitudeTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => IpV6AccessNetworkIdentifierSubOptionGeoLocation.CreateFromRealValues(0, 180.1));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionGeoLocationCreateFromRealValuesLongitudeTooSmall()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => IpV6AccessNetworkIdentifierSubOptionGeoLocation.CreateFromRealValues(0, -180.1));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionGeoLocationDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionAccessNetworkIdentifier(
                                    new IpV6AccessNetworkIdentifierSubOptions(new IpV6AccessNetworkIdentifierSubOptionGeoLocation(0, 0))))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }
       
        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionGeoLocationLatitudeIntegerTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6AccessNetworkIdentifierSubOptionGeoLocation((UInt24)0x7FFFFF, 0));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionGeoLocationLatitudeIntegerTooSmall()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6AccessNetworkIdentifierSubOptionGeoLocation((UInt24)0x800000, 0));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionGeoLocationLongitudeIntegerTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6AccessNetworkIdentifierSubOptionGeoLocation(0, (UInt24)0x7FFFFF));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionGeoLocationLongitudeIntegerTooSmall()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6AccessNetworkIdentifierSubOptionGeoLocation(0, (UInt24)0x800000));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionNetworkIdentifierAccessPointNameTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6AccessNetworkIdentifierSubOptionNetworkIdentifier(false, DataSegment.Empty, new DataSegment(new byte[256])));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionNetworkIdentifierDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionAccessNetworkIdentifier(
                                    new IpV6AccessNetworkIdentifierSubOptions(
                                        new IpV6AccessNetworkIdentifierSubOptionNetworkIdentifier(false, DataSegment.Empty, DataSegment.Empty))))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionNetworkIdentifierDataTooShortForAccessPointName()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionAccessNetworkIdentifier(
                                    new IpV6AccessNetworkIdentifierSubOptions(
                                        new IpV6AccessNetworkIdentifierSubOptionNetworkIdentifier(false, DataSegment.Empty, new DataSegment(new byte[1])))))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionNetworkIdentifierDataTooShortForNetworkName()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionAccessNetworkIdentifier(
                                    new IpV6AccessNetworkIdentifierSubOptions(
                                        new IpV6AccessNetworkIdentifierSubOptionNetworkIdentifier(false, new DataSegment(new byte[1]), DataSegment.Empty))))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionNetworkIdentifierNetworkNameTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6AccessNetworkIdentifierSubOptionNetworkIdentifier(false, new DataSegment(new byte[256]), DataSegment.Empty));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionNetworkIdentifierNullAccessPointName()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6AccessNetworkIdentifierSubOptionNetworkIdentifier(false, DataSegment.Empty, null));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionNetworkIdentifierNullNetworkName()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6AccessNetworkIdentifierSubOptionNetworkIdentifier(false, null, DataSegment.Empty));
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionOperatorIdentifierDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionAccessNetworkIdentifier(
                                    new IpV6AccessNetworkIdentifierSubOptions(
                                        new IpV6AccessNetworkIdentifierSubOptionOperatorIdentifier(
                                            IpV6AccessNetworkIdentifierOperatorIdentifierType.PrivateEnterpriseNumber, DataSegment.Empty))))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 2 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6AccessNetworkIdentifierSubOptionUnknown()
        {
            IpV6AccessNetworkIdentifierSubOptionUnknown subOption =
                new IpV6AccessNetworkIdentifierSubOptionUnknown((IpV6AccessNetworkIdentifierSubOptionType)100, DataSegment.Empty);
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionAccessNetworkIdentifier(
                                    new IpV6AccessNetworkIdentifierSubOptions(subOption)))))
                });
            Assert.True(packet.IsValid);
            IpV6AccessNetworkIdentifierSubOption actualSubOption =
                ((IpV6MobilityOptionAccessNetworkIdentifier)((IpV6ExtensionHeaderMobility)packet.Ethernet.IpV6.ExtensionHeaders[0]).MobilityOptions[0]).
                    SubOptions[0];
            Assert.Equal(subOption, actualSubOption);
            Assert.Equal(subOption.GetHashCode(), actualSubOption.GetHashCode());
        }

        [Fact]
        public void IpV6FlowIdentificationSubOptionTrafficSelectorDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionFlowIdentification(
                                    0, 0, IpV6FlowIdentificationStatus.FlowBindingSuccessful,
                                    new IpV6FlowIdentificationSubOptions(
                                        new IpV6FlowIdentificationSubOptionTrafficSelector(IpV6FlowIdentificationTrafficSelectorFormat.IpV4Binary,
                                                                                           DataSegment.Empty))))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 8 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6FlowIdentificationSubOptionUnknown()
        {
            IpV6FlowIdentificationSubOptionUnknown subOption =
                new IpV6FlowIdentificationSubOptionUnknown((IpV6FlowIdentificationSubOptionType)100, DataSegment.Empty);
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionFlowIdentification(0, 0, IpV6FlowIdentificationStatus.FlowIdentifierNotFound,
                                                                         new IpV6FlowIdentificationSubOptions(subOption)))))
                });
            Assert.True(packet.IsValid);
            IpV6FlowIdentificationSubOption actualSubOption =
                ((IpV6MobilityOptionFlowIdentification)((IpV6ExtensionHeaderMobility)packet.Ethernet.IpV6.ExtensionHeaders[0]).MobilityOptions[0]).SubOptions[0];
            Assert.Equal(subOption, actualSubOption);
            Assert.Equal(subOption.GetHashCode(), actualSubOption.GetHashCode());
        }

        [Fact]
        public void IpV6MobilityOptionAccessNetworkIdentifierDataTooShortForReadingSubOption()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionAccessNetworkIdentifier(
                                    new IpV6AccessNetworkIdentifierSubOptions(
                                        new IpV6AccessNetworkIdentifierSubOptionOperatorIdentifier(
                                            IpV6AccessNetworkIdentifierOperatorIdentifierType.PrivateEnterpriseNumber, DataSegment.Empty))))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 24 + 1] -= 2;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionAccessNetworkIdentifierDataTooShortFullSubOption()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionAccessNetworkIdentifier(
                                    new IpV6AccessNetworkIdentifierSubOptions(
                                        new IpV6AccessNetworkIdentifierSubOptionOperatorIdentifier(
                                            IpV6AccessNetworkIdentifierOperatorIdentifierType.PrivateEnterpriseNumber, new DataSegment(new byte[10])))))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 24 + 1] -= 5;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionAccessNetworkIdentifierNullSubOptions()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6MobilityOptionAccessNetworkIdentifier(null));
        }

        [Fact]
        public void IpV6MobilityOptionAccessNetworkIdentifierSubOptionsTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                new IpV6MobilityOptionAccessNetworkIdentifier(
                    new IpV6AccessNetworkIdentifierSubOptions(
                        new IpV6AccessNetworkIdentifierSubOptionOperatorIdentifier(IpV6AccessNetworkIdentifierOperatorIdentifierType.PrivateEnterpriseNumber,
                                                                                   new DataSegment(new byte[254])))));
        }
        
        [Fact]
        public void IpV6MobilityOptionAccessTechnologyTypeDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionAccessTechnologyType(IpV6AccessTechnologyType.Ethernet))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionAlternateCareOfAddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionAlternateCareOfAddress(IpV6Address.Zero))))

                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionAlternateIpV4CareOfAddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionAlternateIpV4CareOfAddress(IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionAuthenticationDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionAuthentication(IpV6AuthenticationSubtype.HomeAgent, 0, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionBindingAuthorizationDataForFmIpV6DataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionBindingAuthorizationDataForFmIpV6(0, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionBindingIdentifierDataBadLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionBindingIdentifier(0, IpV6BindingAcknowledgementStatus.InsufficientResources, false,
                                                                                            0, IpV6Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionBindingIdentifierDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionBindingIdentifier(0, IpV6BindingAcknowledgementStatus.InsufficientResources, false,
                                                                                            0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionBindingIdentifierPriorityTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionBindingIdentifier(0, IpV6BindingAcknowledgementStatus.AcceptedBut, false, 0x80));
        }

        [Fact]
        public void IpV6MobilityOptionBindingRefreshAdviceDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionBindingRefreshAdvice(0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionCareOfTestCreateInstanceDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionCareOfTest(0))))

                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionCareOfTestInitDataTooLong()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionCareOfTestInit())))

                });
            Assert.True(packet.IsValid);
            ++packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionCgaParametersRequestDataTooLong()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionCryptographicallyGeneratedAddressParametersRequest())))
                });
            Assert.True(packet.IsValid);
            ++packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionCgaParametersTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionCryptographicallyGeneratedAddressParameters(new DataSegment(new byte[256])));
        }

        [Fact]
        public void IpV6MobilityOptionContextRequestDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionContextRequest(new IpV6MobilityOptionContextRequestEntry(0, DataSegment.Empty)))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionContextRequestDataTooShortForRequestLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionContextRequest(new IpV6MobilityOptionContextRequestEntry(0, new DataSegment(new byte[10]))))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionContextRequestEntryEquals()
        {
            Assert.Equal(new IpV6MobilityOptionContextRequestEntry(0, DataSegment.Empty), new IpV6MobilityOptionContextRequestEntry(0, DataSegment.Empty));
        }

        [Fact]
        public void IpV6MobilityOptionContextRequestEntryNullOption()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6MobilityOptionContextRequestEntry(0, null));
        }

        [Fact]
        public void IpV6MobilityOptionContextRequestEntryOptionLengthTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionContextRequestEntry(0, new DataSegment(new byte[256])));
        }

        [Fact]
        public void IpV6MobilityOptionContextRequestTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionContextRequest(
                              new IpV6MobilityOptionContextRequestEntry(0, new DataSegment(new byte[100])),
                              new IpV6MobilityOptionContextRequestEntry(0, new DataSegment(new byte[100])),
                              new IpV6MobilityOptionContextRequestEntry(0, new DataSegment(new byte[100]))));
        }
        
        [Fact]
        public void IpV6MobilityOptionCryptographicallyGeneratedAddressParametersNullCryptographicallyGeneratedAddressParameters()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6MobilityOptionCryptographicallyGeneratedAddressParameters(null));
        }

        [Fact]
        public void IpV6MobilityOptionDnsUpdateDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionDnsUpdate(IpV6DnsUpdateStatus.ReasonUnspecified, false, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionFlowIdentificationDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionFlowIdentification(0, 0, IpV6FlowIdentificationStatus.FlowBindingSuccessful, IpV6FlowIdentificationSubOptions.None))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionFlowIdentificationNullSubOptions()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6MobilityOptionFlowIdentification(0, 0, IpV6FlowIdentificationStatus.FlowBindingSuccessful, null));
        }

        [Fact]
        public void IpV6MobilityOptionFlowIdentificationSubOptionsTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionFlowIdentification(0, 0, IpV6FlowIdentificationStatus.FlowBindingSuccessful,
                                                                   new IpV6FlowIdentificationSubOptions(new IpV6FlowIdentificationSubOptionPadN(500))));
        }

        [Fact]
        public void IpV6MobilityOptionFlowSummaryConstructors()
        {
            IEnumerable<ushort> flowIdentifiersEnumerable = new ushort[1];
            IList<ushort> flowIdentifiersIList = new ushort[1];
            Assert.Equal(new IpV6MobilityOptionFlowSummary(flowIdentifiersEnumerable), new IpV6MobilityOptionFlowSummary(flowIdentifiersIList));
        }

        [Fact]
        public void IpV6MobilityOptionFlowSummaryDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionFlowSummary(new ushort[1]))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }
        
        [Fact]
        public void IpV6MobilityOptionFlowSummaryNoIdentifiers()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionFlowSummary(new ushort[0]));
        }

        [Fact]
        public void IpV6MobilityOptionGreKeyDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionGreKey(0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionHandoffIndicatorDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionHandoffIndicator(IpV6HandoffIndicator.HandoffBetweenTwoDifferentInterfacesOfTheMobileNode))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionHomeNetworkPrefixDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionHomeNetworkPrefix(0, IpV6Address.Zero))))

                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionIpV4AddressAcknowledgementDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionIpV4AddressAcknowledgement(IpV6AddressAcknowledgementStatus.Success, 0, IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionIpV4AddressAcknowledgementPrefixLengthTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionIpV4AddressAcknowledgement(IpV6AddressAcknowledgementStatus.Success, 0x40, IpV4Address.Zero));
        }

        [Fact]
        public void IpV6MobilityOptionIpV4CareOfAddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionIpV4CareOfAddress(IpV4Address.Zero))))

                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionIpV4DefaultRouterAddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionIpV4DefaultRouterAddress(IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionIpV4DhcpSupportModeDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionIpV4DhcpSupportMode(false))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionIpV4HomeAddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionIpV4HomeAddress(0, false, IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionIpV4HomeAddressPrefixLengthTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionIpV4HomeAddress(0x40, false, IpV4Address.Zero));
        }

        [Fact]
        public void IpV6MobilityOptionIpV4HomeAddressReplyDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionIpV4HomeAddressReply(IpV6IpV4HomeAddressReplyStatus.Success, 0, IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionIpV4HomeAddressReplyPrefixLengthTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionIpV4HomeAddressReply(IpV6IpV4HomeAddressReplyStatus.Success, 0x40, IpV4Address.Zero));
        }

        [Fact]
        public void IpV6MobilityOptionIpV4HomeAddressRequestDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionIpV4HomeAddressRequest(0, IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }
        
        [Fact]
        public void IpV6MobilityOptionIpV4HomeAddressRequestPrefixLengthTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionIpV4HomeAddressRequest(0x40, IpV4Address.Zero));
        }

        [Fact]
        public void IpV6MobilityOptionIpV6AddressPrefixDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionIpV6AddressPrefix(IpV6MobilityIpV6AddressPrefixCode.NewCareOfAddress, 0,
                                                                                            IpV6Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionIpV6AddressPrefixPrefixLengthTooBig()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionIpV6AddressPrefix(IpV6MobilityIpV6AddressPrefixCode.NewCareOfAddress, 129, IpV6Address.Zero));
        }

        [Fact]
        public void IpV6MobilityOptionLinkLayerAddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionLinkLayerAddress(IpV6MobilityLinkLayerAddressCode.MobilityNode, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionLinkLocalAddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionLinkLocalAddress(IpV6Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionLoadInformationDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionLoadInformation(0, 0, 0, 0, 0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionLocalMobilityAnchorAddressBadCode()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionLocalMobilityAnchorAddress(IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 24 + 2] = 5;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionLocalMobilityAnchorAddressDataLengthDoesntMatchIpV4()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionLocalMobilityAnchorAddress(IpV4Address.Zero),
                                new IpV6MobilityOptionPadN(10))))
                });
            Assert.True(packet.IsValid);
            ++packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionLocalMobilityAnchorAddressDataLengthDoesntMatchIpV6()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionLocalMobilityAnchorAddress(IpV6Address.Zero))))
                });
            Assert.True(packet.IsValid);
            ++packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }
        
        [Fact]
        public void IpV6MobilityOptionLocalMobilityAnchorAddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionLocalMobilityAnchorAddress(IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 24 + 1] -= 5;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionMobileAccessGatewayIpV6AddressDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionMobileAccessGatewayIpV6Address(IpV6Address.Zero))))

                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionMobileAccessGatewayIpV6AddressWrongAddressLength()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionMobileAccessGatewayIpV6Address(IpV6Address.Zero))))

                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 3];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionMobileNetworkPrefixDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionMobileNetworkPrefix(0, IpV6Address.Zero))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionMobileNodeGroupIdentifierDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionMobileNodeGroupIdentifier(IpV6MobileNodeGroupIdentifierSubtype.BulkBindingUpdateGroup, 0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionMobileNodeIdentifierCreateInstanceDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionMobileNodeIdentifier((IpV6MobileNodeIdentifierSubtype)2, DataSegment.Empty))))

                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionMobileNodeIdentifierCreateInstanceNetworkAccessIdentifierTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionMobileNodeIdentifier(IpV6MobileNodeIdentifierSubtype.NetworkAccessIdentifier,
                                                                                               new DataSegment(new byte[1])))))

                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionMobileNodeIdentifierEquals()
        {
            Assert.Equal(new IpV6MobilityOptionMobileNodeIdentifier(IpV6MobileNodeIdentifierSubtype.NetworkAccessIdentifier, new DataSegment(new byte[1])),
                            new IpV6MobilityOptionMobileNodeIdentifier(IpV6MobileNodeIdentifierSubtype.NetworkAccessIdentifier, new DataSegment(new byte[1])));
            Assert.NotEqual(
                new IpV6MobilityOptionMobileNodeIdentifier(IpV6MobileNodeIdentifierSubtype.NetworkAccessIdentifier, new DataSegment(new byte[1])),
                new IpV6MobilityOptionMobileNodeIdentifier((IpV6MobileNodeIdentifierSubtype)2, new DataSegment(new byte[1])));
            Assert.NotEqual(
                new IpV6MobilityOptionMobileNodeIdentifier(IpV6MobileNodeIdentifierSubtype.NetworkAccessIdentifier, new DataSegment(new byte[1])),
                new IpV6MobilityOptionMobileNodeIdentifier(IpV6MobileNodeIdentifierSubtype.NetworkAccessIdentifier, new DataSegment(new byte[2])));
            Assert.False(
                new IpV6MobilityOptionMobileNodeIdentifier(IpV6MobileNodeIdentifierSubtype.NetworkAccessIdentifier, new DataSegment(new byte[1])).Equals(null));
        }

        [Fact]
        public void IpV6MobilityOptionMobileNodeIdentifierNullIdentifier()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6MobilityOptionMobileNodeIdentifier(IpV6MobileNodeIdentifierSubtype.NetworkAccessIdentifier, null));
        }

        [Fact]
        public void IpV6MobilityOptionMobileNodeIdentifierIdentifierTooShort()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionMobileNodeIdentifier(IpV6MobileNodeIdentifierSubtype.NetworkAccessIdentifier, DataSegment.Empty));
        }

        [Fact]
        public void IpV6MobilityOptionMobileNodeLinkLayerIdentifierDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionMobileNodeLinkLayerIdentifier(DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionMobileNodeLinkLocalAddressInterfaceIdentifierDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(
                                new IpV6MobilityOptionMobileNodeLinkLocalAddressInterfaceIdentifier(0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionNatDetectionDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionNatDetection(false, 0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionNonceIndicesDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionNonceIndexes(0, 0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionRedirectCapabilityDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionRedirectCapability())))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionRedirectCreateInstanceDataShorterThanMinimum()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionRedirect(IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 24 + 1] = 1;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionRedirectCreateInstanceDataTooShortForIpV4()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionRedirect(IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 24 + 1] = 3;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionRedirectCreateInstanceDataTooShortForIpV6()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionRedirect(IpV6Address.Zero))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 24 + 1] = 15;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionRedirectCreateInstanceNotIpV6OrIpV4()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionRedirect(IpV4Address.Zero))))
                });
            Assert.True(packet.IsValid);
            packet.Buffer[14 + 40 + 24 + 2] = 0;
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionReplayProtectionDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionReplayProtection(0))))

                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionRestartCounterDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionRestartCounter(0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionServiceSelectionConstructorDataTooShort()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionServiceSelection(DataSegment.Empty));
        }

        [Fact]
        public void IpV6MobilityOptionServiceSelectionDataTooLong()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new IpV6MobilityOptionServiceSelection(new DataSegment(new byte[256])));
        }

        [Fact]
        public void IpV6MobilityOptionServiceSelectionDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionServiceSelection(new DataSegment(new byte[1])))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionServiceSelectionNullIdentifier()
        {
            Assert.Throws<ArgumentNullException>(() => new IpV6MobilityOptionServiceSelection(null));
        }

        [Fact]
        public void IpV6MobilityOptionTimestampDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionTimestamp(0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionTransientBindingDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionTransientBinding(false, 0))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        [Fact]
        public void IpV6MobilityOptionUnknown()
        {
            Random random = new Random();
            DataSegment data = random.NextDataSegment(random.NextInt(0, 100));
            IpV6MobilityOptionUnknown option = new IpV6MobilityOptionUnknown((IpV6MobilityOptionType)0xBB, data);
            Assert.Equal(data, option.Data);
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders = new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue,
                                                                    IpV6Address.Zero, new IpV6MobilityOptions(option)))
                });
            Assert.True(packet.IsValid);
            Assert.Equal(option, ((IpV6ExtensionHeaderMobility)packet.Ethernet.IpV6.ExtensionHeaders[0]).MobilityOptions[0]);
        }

        [Fact]
        public void IpV6MobilityOptionVendorSpecificDataTooShort()
        {
            Packet packet = PacketBuilder.Build(
                DateTime.Now,
                new EthernetLayer(),
                new IpV6Layer
                {
                    ExtensionHeaders =
                        new IpV6ExtensionHeaders(
                        new IpV6ExtensionHeaderMobilityBindingError(
                            IpV4Protocol.Skip, 0, IpV6BindingErrorStatus.UnrecognizedMobilityHeaderTypeValue, IpV6Address.Zero,
                            new IpV6MobilityOptions(new IpV6MobilityOptionVendorSpecific(0, 0, DataSegment.Empty))))
                });
            Assert.True(packet.IsValid);
            --packet.Buffer[14 + 40 + 24 + 1];
            Packet invalidPacket = new Packet(packet.Buffer, DateTime.Now, DataLinkKind.Ethernet);
            Assert.False(invalidPacket.IsValid);
        }

        // Other tests.

        [Fact]
        public void PppFrameCheckSequenceCalculatorCalculateFrameCheckSequence16NullBytes()
        {
            Assert.Throws<ArgumentNullException>(() => PointToPointProtocolFrameCheckSequenceCalculator.CalculateFrameCheckSequence16(0, null));
        }
    }
}
