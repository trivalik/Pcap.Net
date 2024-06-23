using System;
using System.Collections.Generic;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets;

namespace PcapDotNet.Core
{
    /// <summary>
    /// A file to write packets.
    /// </summary>
    public sealed class PacketDumpFile : IDisposable
    {
        private IntPtr /*pcap_dumper_t* */ _pcapDumper;
        private readonly string _filename;

        internal PacketDumpFile(PcapHandle /*pcap_t* */ pcapDescriptor, string filename)
        {
            _filename = filename;

            // TODO: Use pcap_dump_fopen() to support Unicode filenames once it's available. See http://www.winpcap.org/pipermail/winpcap-users/2011-February/004273.html
            _pcapDumper = Interop.Pcap.pcap_dump_open(pcapDescriptor, filename);
            if (_pcapDumper == IntPtr.Zero)
                throw new InvalidOperationException("Error opening output file " + filename + " Error: " + PcapError.GetErrorMessage(pcapDescriptor));
        }

        /// <summary>
        /// Save a packet to disk.
        /// Outputs a packet to the "savefile" opened with PacketCommunicator.OpenDump().
        /// </summary>
        /// <param name="packet">The packet to write to disk.</param>
        public void Dump(Packet packet)
        {
            if (packet == null)
                throw new ArgumentNullException(nameof(packet));

            using (var header = new PcapPacketHeaderHandle(packet))
            {
                unsafe
                {
                    fixed (byte* bytes = packet.Buffer)
                        Interop.Pcap.pcap_dump(_pcapDumper, header.Pointer, new IntPtr(bytes));
                }
            }
        }

        /// <summary>
        /// Flushes the output buffer to the ``savefile,'' so that any packets written with Dump() but not yet written to the ``savefile'' will be written.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown on error.</exception>
        public void Flush()
        {
            if (Interop.Pcap.pcap_dump_flush(_pcapDumper) != 0)
                throw new InvalidOperationException("Failed flushing to file " + _filename);
        }

        /// <summary>
        /// Return the file position for a "savefile".
        /// Returns the current file position for the "savefile", representing the number of bytes written by PacketCommunicator.OpenDump() and Dump().
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown on error.</exception>
        public int Position
        {
            get
            {
                long position = Interop.Pcap.pcap_dump_ftell(_pcapDumper);
                if (position == -1)
                    throw new InvalidOperationException("Failed getting position");
                return (int)position;
            }
        }

        /// <summary>
        /// Closes a savefile.
        /// </summary>
        public void Dispose()
        {
            Interop.Pcap.pcap_dump_close(_pcapDumper);
        }

        /// <summary>
        /// Creates a dump file and saves the given packets to disk.
        /// This method is useful when you've got packets to save but no device.
        /// </summary>
        /// <param name="fileName">The name of the dump file.</param>
        /// <param name="dataLink">The data link of the packets saved globally in the dump file.</param>
        /// <param name="snapshotLength">The dimension of the packet portion (in bytes) that is used when writing the packets. 65536 guarantees that the whole packet will be captured on all the link layers.</param>
        /// <param name="packets">The packets to save to the dump file.</param>
        public static void Dump(string fileName, PcapDataLink dataLink, int snapshotLength, IEnumerable<Packet> packets)
        {
            if (packets == null)
                throw new ArgumentNullException(nameof(packets));

            using (var pcapDescriptor = Interop.Pcap.pcap_open_dead(dataLink.Value, snapshotLength))
            {
                if (pcapDescriptor.IsInvalid)
                    throw new InvalidOperationException("Unable to open open a dead capture");

                using (var dumpFile = new PacketDumpFile(pcapDescriptor, fileName))
                {
                    foreach (var packet in packets)
                    {
                        dumpFile.Dump(packet);
                    }
                }
            }
        }

        /// <inheritdoc cref="PacketDumpFile.Dump(string, PcapDataLink, int, IEnumerable{Packet})"/>
        public static void Dump(string fileName, DataLinkKind dataLink, int snapshotLength, IEnumerable<Packet> packets)
        {
            Dump(fileName, new PcapDataLink(dataLink), snapshotLength, packets);
        }
    }
}
