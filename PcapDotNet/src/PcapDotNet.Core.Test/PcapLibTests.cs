using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace PcapDotNet.Core.Test
{
    /// <summary>
    /// Summary description for PcapLibTests.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class PcapLibTests
    {
        [Fact]
        public void VersionTest()
        {
            const string VersionNumberRegex = @"[0-9]+\.[0-9]+(?:\.| beta)[0-9]+(?:\.[0-9]+)?";
            const string LibpcapVersionRegex = @"(?:[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)|(?:[0-9]\.[0-9] branch [0-9]_[0-9]_rel0b \([0-9]+\))";
            // WinPcap version 4.1.1 (packet.dll version 4.1.0.1753), based on libpcap version 1.0 branch 1_0_rel0b (20091008)
            // WinPcap version 4.1 beta5 (packet.dll version 4.1.0.1452), based on libpcap version 1.0.0
            const string VersionRegex = "^WinPcap version " + VersionNumberRegex + @" \(packet\.dll version " + VersionNumberRegex + @"\), based on libpcap version " + LibpcapVersionRegex + "$";
            string version = PcapLibrary.Version;
            Assert.Matches(VersionRegex, version);
        }
    }
}
