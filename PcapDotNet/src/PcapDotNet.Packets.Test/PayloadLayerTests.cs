using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using PcapDotNet.Base;
using PcapDotNet.Packets.TestUtils;
using Xunit;

namespace PcapDotNet.Packets.Test
{
    /// <summary>
    /// Summary description for PayloadLayerTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PayloadLayerTests
    {
        [Fact]
        public void PayloadLayerEqualsTest()
        {
            Random random = new Random();

            for (int i = 0; i != 1000; ++i)
            {
                PayloadLayer layer = random.NextPayloadLayer(random.Next(100));
                Assert.NotNull(layer);
                Assert.Equal(layer, new PayloadLayer
                                           {
                                               Data = layer.Data
                                           });
                Assert.NotEqual(layer, new PayloadLayer
                                              {
                                                  Data = new Datagram(layer.Data.Concat<byte>(1).ToArray())
                                              });
                if (layer.Length > 1)
                {
                    Assert.NotEqual(layer, new PayloadLayer
                                                  {
                                                      Data = random.NextDatagram(layer.Length)
                                                  });
                }
            }
        }
    }
}