using System;
using System.Diagnostics.CodeAnalysis;
using Xunit;


namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for SequenceTest
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class SequenceTest
    {
        [Fact]
        public void GetHashCodeNullValue1Test()
        {
            Assert.Equal(1.GetHashCode(), Sequence.GetHashCode(null, 1));
        }

        [Fact]
        public void GetHashCodeNullValue2Test()
        {
            Assert.Equal(1.GetHashCode(), Sequence.GetHashCode(1, null));
        }

        [Fact]
        public void GetHashCodeNullValue3Test()
        {
            Assert.Equal(Sequence.GetHashCode(1, 2), Sequence.GetHashCode(1, 2, null));
        }

        [Fact]
        public void GetHashCodeNullValuesTest()
        {
            Assert.Throws<ArgumentNullException>(() => Sequence.GetHashCode(null));
        }
    }
}