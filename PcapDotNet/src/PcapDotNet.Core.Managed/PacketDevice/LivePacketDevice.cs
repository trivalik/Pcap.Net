using PcapDotNet.Core.Native;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;

namespace PcapDotNet.Core
{
    /// <summary>
    /// A live interface.
    /// </summary>
    public sealed class LivePacketDevice : PacketDevice
    {
        /// <summary>
        /// Create a list of local machine network devices that can be opened with Open().
        /// Platform independent.
        /// </summary>
        /// <returns>
        /// A readonly collection of LivePacketDevices.
        /// </returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown if some errors occurred. 
        /// An error could be due to several reasons: 
        ///   <list type="bullet">
        ///     <item>libpcap/WinPcap was not installed on the local/remote host.</item>
        ///     <item>The user does not have enough privileges to list the devices.</item>
        ///     <item>A network problem.</item>
        ///     <item>other errors (not enough memory and others).</item>
        ///   </list>
        /// </exception>
        /// <remarks>
        /// There may be network devices that cannot be opened with Open() by the process calling AllLocalMachine, because, for example, that process might not have sufficient privileges to open them for capturing; if so, those devices will not appear on the list.
        /// </remarks>
        public static ReadOnlyCollection<LivePacketDevice> AllLocalMachine
        {
            get
            {
                var devicePtr = IntPtr.Zero;
                var errorBuffer = Pcap.CreateErrorBuffer();
                var auth = default(PcapUnmanagedStructures.pcap_rmtauth); //auth is not needed

                var result = Interop.Pcap.pcap_findalldevs_ex(Pcap.PCAP_SRC_IF_STRING, ref auth, ref devicePtr, errorBuffer);
                if (result < 0)
                {
                    PcapError.ThrowInvalidOperation("Failed getting devices. Error: " + errorBuffer.ToString(), null);
                }
                try
                {
                    var deviceList = new List<LivePacketDevice>();
                    var nextDevPtr = devicePtr;
                    while (nextDevPtr != IntPtr.Zero)
                    {
                        // Marshal pointer into a struct
                        var pcap_if_unmanaged = Marshal.PtrToStructure<PcapUnmanagedStructures.pcap_if>(nextDevPtr);

                        deviceList.Add(new LivePacketDevice(pcap_if_unmanaged));


                        nextDevPtr = pcap_if_unmanaged.Next;
                    }
                    return new ReadOnlyCollection<LivePacketDevice>(deviceList);
                }
                finally
                {
                    Interop.Pcap.pcap_freealldevs(devicePtr);
                }
            }
        }

        private LivePacketDevice(PcapUnmanagedStructures.pcap_if device)
        {
            Name = device.Name;
            Description = device.Description;
            Attributes = (DeviceAttributes)device.Flags;

            var addresses = new List<DeviceAddress>();
            var nextaddressPtr = device.Addresses;
            while (nextaddressPtr != IntPtr.Zero)
            {
                var addr = Marshal.PtrToStructure<PcapUnmanagedStructures.pcap_addr>(nextaddressPtr);

                addresses.Add(new DeviceAddress(addr));

                nextaddressPtr = addr.Next;
            }
            Addresses = new ReadOnlyCollection<DeviceAddress>(addresses);
        }

        public override string Name { get; }

        public override string Description { get; }

        public override DeviceAttributes Attributes { get; }

        public override ReadOnlyCollection<DeviceAddress> Addresses { get; }

        public override PacketCommunicator Open(int snapshotLength, PacketDeviceOpenAttributes attributes, int readTimeout)
        {
            throw new NotImplementedException();
        }
    }
}
