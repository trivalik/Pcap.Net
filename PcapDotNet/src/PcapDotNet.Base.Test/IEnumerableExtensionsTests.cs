using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for IEnumerableExtensionsTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    // ReSharper disable InconsistentNaming
    public class IEnumerableExtensionsTests
// ReSharper restore InconsistentNaming
    {
        [Fact]
        public void SequenceToStringTest()
        {
            int[] sequence = new[]{1,2,3,4,5};

            Assert.Equal("12345",sequence.SequenceToString());
        }

        [Fact]
        public void SequenceGetHashCodeTest()
        {
            int[] sequence = new[]{1,2,3,4,5};

            Assert.Equal(1.GetHashCode() ^ 2.GetHashCode() ^ 3.GetHashCode() ^ 4.GetHashCode() ^ 5.GetHashCode(), sequence.SequenceGetHashCode());
        }

        [Fact]
        public void BytesSequenceGetHashCodeTest()
        {
            byte[] sequence = new byte[] { 1, 2, 3, 4, 5 };

            Assert.Equal((int)BitSequence.Merge(4, 3, 2, 1) ^ 5, sequence.BytesSequenceGetHashCode());
        }

        [Fact]
        public void ConcatTest()
        {
            int[] sequence = new[] {1, 2, 3, 4, 5};

            Assert.True(sequence.SequenceEqual(new[] {1,2,3}.Concat(4, 5)));
        }

        [Fact]
        public void SequenceToStringNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => IEnumerableExtensions.SequenceToString<int>(null));
        }

        [Fact]
        public void XorTest()
        {
            int[] intValues = new[] {0x0001, 0x0020, 0x0300, 0x4000};
            Assert.Equal(0x4321, intValues.Xor());

            long[] longValues = new[]
                                {
                                    0x00000001L, 0x00000020L, 0x00000300L, 0x00004000L,
                                    0x00050000L, 0x00600000L, 0x07000000L, 0x80000000L
                                };
            Assert.Equal(0x87654321L, longValues.Xor());
        }

        [Fact]
        public void IsStrictOrderedTest()
        {
            Assert.True(new[] {1, 2, 3, 4, 5}.IsStrictOrdered(value => value, Comparer<int>.Default));
            Assert.False(new[] { 1, 2, 3, 3, 5 }.IsStrictOrdered(value => value, Comparer<int>.Default));
            Assert.False(new[] { 1, 2, 3, 4, 3 }.IsStrictOrdered(value => value, Comparer<int>.Default));
        }

        [Fact]
        public void IsStrictOrderedNullComparerTest()
        {
            Assert.Throws<ArgumentNullException>(() => new[] { 1, 2, 3, 4, 5 }.IsStrictOrdered(value => value, null));
        }
    }
}