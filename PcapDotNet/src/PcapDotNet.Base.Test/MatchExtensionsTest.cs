using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using Xunit;

namespace PcapDotNet.Base.Test
{
    /// <summary>
    /// Summary description for MatchExtensionsTest
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class MatchExtensionsTest
    {
        [Fact]
        public void GroupCapturesValuesNullMatchTest()
        {
            Match match = null;
            Assert.Throws<ArgumentNullException>(() => match.GroupCapturesValues("someGroup"));
        }
    }
}