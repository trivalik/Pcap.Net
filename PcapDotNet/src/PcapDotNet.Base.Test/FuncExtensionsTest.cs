using System;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for FuncExtensionsTest
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class FuncExtensionsTest
    {
        [Fact]
        public void GenerateArrayNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => FuncExtensions.GenerateArray<int>(null, 100));
        }
    }
}