using System;
using System.Diagnostics.CodeAnalysis;
using PcapDotNet.TestUtils;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for UInt24Tests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class UInt24Tests
    {
        [Fact]
        public void UInt24Test()
        {
            Random random = new Random();
            for (int i = 0; i != 1000; ++i)
            {
                UInt24 value = random.NextUInt24();

                Assert.Equal(value, value);
                // ReSharper disable EqualExpressionComparison
                Assert.True(value == value);
                Assert.False(value != value);
                // ReSharper restore EqualExpressionComparison
                Assert.NotEqual(value, (UInt24)(((value & 0x00FFFF) + 1) | value & 0xFF0000));
                Assert.NotEqual(value, (UInt24)((value & 0x00FFFF) | ((value & 0xFF0000) + 0x010000)));
                Assert.Equal(((int)value).ToString(), value.ToString());
            }
        }
    }
}