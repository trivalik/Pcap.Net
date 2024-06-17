using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for DictionaryExtensionsTests
    /// </summary>
    [ExcludeFromCodeCoverage]
    // ReSharper disable InconsistentNaming
    public class IDictionaryExtensionsTests
    // ReSharper restore InconsistentNaming
    {
        [Fact]
        public void DictionaryEqualsTest()
        {
            // Both null
            Dictionary<int, int> dic1 = null;
            Dictionary<int, int> dic2 = null;
            Assert.True(dic1.DictionaryEquals(dic2));
            Assert.True(dic2.DictionaryEquals(dic1));
      
            // One null
            dic1 = new Dictionary<int, int>();
            Assert.False(dic1.DictionaryEquals(dic2));
            Assert.False(dic2.DictionaryEquals(dic1));

            // Both empty
            dic2 = new Dictionary<int, int>();
            Assert.True(dic1.DictionaryEquals(dic2));
            Assert.True(dic2.DictionaryEquals(dic1));

            // Different count
            dic1.Add(1,1);
            Assert.False(dic1.DictionaryEquals(dic2));
            Assert.False(dic2.DictionaryEquals(dic1));

            // Different key
            dic2.Add(2, 1);
            Assert.False(dic1.DictionaryEquals(dic2));
            Assert.False(dic2.DictionaryEquals(dic1));

            // Different value
            dic1.Add(2, 1);
            dic2.Add(1, 2);
            Assert.False(dic1.DictionaryEquals(dic2));
            Assert.False(dic2.DictionaryEquals(dic1));
        }

        [Fact]
        public void DictionaryEqualsNullTest()
        {
            Assert.Throws<ArgumentNullException>(() => new Dictionary<int, int>().DictionaryEquals(new Dictionary<int, int>(), null));
        }
    }
}