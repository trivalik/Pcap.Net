using System;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for DateTimeExtensionsTest
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class DateTimeExtensionsTest
    {
        [Fact]
        public void AddMicrosecondsValueTooBigTest()
        {
            DateTime dateTime = DateTime.Now;
            Assert.Throws< ArgumentOutOfRangeException>(() => dateTime.AddMicroseconds((long.MaxValue / TimeSpanExtensions.TicksPerMicrosecond) * 2));
        }

        [Fact]
        public void AddMicrosecondsValueTooSmallTest()
        {
            DateTime dateTime = DateTime.Now;
            Assert.Throws<ArgumentOutOfRangeException>(() => dateTime.AddMicroseconds((long.MinValue / TimeSpanExtensions.TicksPerMicrosecond) * 2));
        }
    }
}