using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for BitSequenceTest
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class BitSequenceTest
    {
        [Fact]
        public void Merge8BoolRandomTest()
        {
            Random random = new Random();
            for (int i = 0; i != 10; ++i)
            {
                byte expectedResult = 0;
                bool[] input = new bool[8];
                for (int bit = 0; bit != 8; ++bit)
                {
                    bool bitValue = random.NextBool();
                    input[bit] = bitValue;
                    expectedResult <<= 1;
                    if (bitValue)
                        ++expectedResult;
                }

                Assert.Equal(expectedResult, BitSequence.Merge(input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7]));
            }
        }
    }
}