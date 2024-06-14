using PcapDotNet.Core.Native;
using System;
using System.Text.RegularExpressions;

namespace PcapDotNet.Core
{
    /// <summary>
    /// This class holds methods for general pcap library functionality.
    /// </summary>
    public sealed class PcapLibrary
    {
        private static readonly Lazy<string> _version = new Lazy<string>(Interop.Pcap.pcap_lib_version);
        private static readonly Lazy<Version> _semanticVersion = new Lazy<Version>(GetSemanticVersion);

        /// <summary>
        /// The Pcap library version string.
        /// </summary>
        /// <example>libpcap version 1.5.1</example>
        /// <example>Npcap version 1.78, based on libpcap version 1.10.4</example>
        public static string Version
        {
            get
            {
                return _version.Value;
                //ToDo: error Handling?
            }

        }

        /// <summary>
        /// Parsed Pcap library (libpcap) version.
        /// </summary>
        public static Version SemanticVersion
        {
            get { return _semanticVersion.Value; }
        }

        private static Version GetSemanticVersion()
        {
            var regex = new Regex(@"libpcap version (\d+\.\d+(\.\d+)?)");
            var match = regex.Match(Version);
            if (match.Success)
            {
                return new Version(match.Groups[1].Value);
            }
            return new Version();
        }
    }
}
