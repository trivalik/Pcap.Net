using System;
using System.Collections.Generic;
using System.Text;
using PcapDotNet.Core.Native;
using PcapDotNet.Packets;

namespace PcapDotNet.Core
{
    /// <summary>
    /// Represents a buffer of packets to be sent.
    /// Note that transmitting a send buffer is much more efficient than performing a series of Send(), because the send buffer is buffered at kernel level drastically decreasing the number of context switches.
    /// </summary>
    public sealed class PacketSendBuffer : IDisposable
    {
        private IntPtr /* pcap_send_queue* */ _pcapSendQueue;
        private int _length;

        /// <summary>
        /// This function allocates a send buffer, i.e. a buffer containing a set of raw packets that will be transimtted on the network with PacketCommunicator.Transmit().
        /// </summary>
        /// <param name="capacity">The size, in bytes, of the buffer, therefore it determines the maximum amount of data that the buffer will contain.</param>
        public PacketSendBuffer(uint capacity)
        {
            throw new NotImplementedException();
            // ToDo: Only works on windows with winpcap or npcap!
            //_pcapSendQueue = Interop.Pcap.pcap_sendqueue_alloc(capacity);
        }

        public int Length => _length;

        /// <summary>
        /// Adds a raw packet at the end of the send buffer.
        /// 'Raw packet' means that the sending application will have to include the protocol headers, since every packet is sent to the network 'as is'. The CRC of the packets needs not to be calculated, because it will be transparently added by the network interface.
        /// </summary>
        /// <param name="packet">The packet to be added to the buffer</param>
        /// <exception cref="System.InvalidOperationException">Thrown on failure.</exception>
        void Enqueue(Packet packet)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Deletes a send buffer and frees all the memory associated with it.
        /// </summary>
        public void Dispose()
        {
            throw new NotImplementedException();
        }

        internal void Transmit(IntPtr /*pcap_t* */ pcapDescriptor, bool isSync)
        {
            throw new NotImplementedException();
        }

    
    }
}
