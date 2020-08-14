using System;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Attributes of a device.
    /// </summary>
    [Flags]
    public enum DeviceAttributes : int
    {
        /// <summary>
        /// No attributes apply.
        /// </summary>
        None     = 0x00000000,

        /// <summary>
        /// Interface is loopback.
        /// </summary>
        Loopback = 0x00000001
    }
}
