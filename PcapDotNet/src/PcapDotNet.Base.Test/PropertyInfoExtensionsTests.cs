using System;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for PropertyInfoExtensionsTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PropertyInfoExtensionsTests
    {
        [Fact]
        public void GetValueNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => PropertyInfoExtensions.GetValue(null, 0));
        }
    }
}