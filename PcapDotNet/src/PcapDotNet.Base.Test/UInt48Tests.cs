using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for UInt48Tests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class UInt48Tests
    {
        [Fact]
        public void ParseTest()
        {
            Random random = new Random();
            for (int i = 0; i != 100; ++i)
            {
                UInt48 expected = (UInt48)random.NextLong(UInt48.MaxValue + 1);

                UInt48 actual = UInt48.Parse(expected.ToString(), NumberStyles.Integer, CultureInfo.InvariantCulture);
                Assert.Equal(expected, actual);

                actual = UInt48.Parse(expected.ToString(), NumberStyles.Integer);
                Assert.Equal(expected, actual);

                actual = UInt48.Parse(expected.ToString(), CultureInfo.InvariantCulture);
                Assert.Equal(expected, actual);

                actual = UInt48.Parse(expected.ToString());
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public void ParseTooBigTest()
        {
            Assert.Throws<OverflowException>(() => UInt48.Parse(ulong.MaxValue.ToString()));
        }

        [Fact]
        public void ParseTooBigTestEvenForUInt64()
        {
            Assert.Throws<OverflowException>(() => UInt48.Parse(ulong.MaxValue + "0"));
        }

        [Fact]
        public void UInt48Test()
        {
            Random random = new Random();
            for (int i = 0; i != 1000; ++i)
            {
                UInt48 value = random.NextUInt48();

                Assert.Equal(value, value);
                // ReSharper disable EqualExpressionComparison
                Assert.True(value == value);
                Assert.False(value != value);
                // ReSharper restore EqualExpressionComparison

                if (value < uint.MaxValue)
                    Assert.Equal(value, uint.Parse(value.ToString()));

                Assert.Equal((byte)value, (byte)(value % 256));
            }
        }
    }
}
