﻿using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using PcapDotNet.Packets;
using static PcapDotNet.Core.Native.PcapUnmanagedStructures;

namespace PcapDotNet.Core.Native
{
    internal class PcapUnixPal : IPcapPal
    {
        public PcapUnixPal()
        {
            PcapHeaderSize = Marshal.SizeOf(typeof(pcap_pkthdr_unix));
        }

        public Encoding StringEncoding { get => Encoding.UTF8; /* libpcap always use UTF-8 when not on Windows */ }

        public int PcapHeaderSize { get; }

        public IntPtr CreatePcapPacketHeaderHandle(Packet packet)
        {
            var header = new pcap_pkthdr_unix
            {
                caplen = packet.OriginalLength,
                len = (uint)packet.Length
            };
            var dt = packet.Timestamp.ToUniversalTime();
            var ts = dt - Interop.UnixEpoch;
            header.ts.tv_sec = (IntPtr)ts.TotalSeconds;
            header.ts.tv_usec = (IntPtr)((ts.TotalMilliseconds - 1000 * (double)header.ts.tv_sec) * 1000);

            var result = Marshal.AllocHGlobal(PcapHeaderSize);
            Marshal.StructureToPtr(header, result, true);
            return result;
        }

        public virtual unsafe PcapPacketHeader CreatePcapPacketHeader(IntPtr /* pcap_pkthdr* */ ptr)
        {
            var pcap_header = (pcap_pkthdr_unix*)ptr;
            var timestamp = PacketTimestamp.PcapTimestampToDateTime(pcap_header->ts);
            return new PcapPacketHeader(timestamp, pcap_header->caplen, pcap_header->len);
        }

        public PcapInterfaceHandle GetAllLocalMachine()
        {
            var handle = new PcapInterfaceHandle();
            var errorBuffer = Pcap.CreateErrorBuffer();

            var result = pcap_findalldevs(ref handle, errorBuffer);
            if (result < 0)
            {
                PcapError.ThrowInvalidOperation("Failed getting devices. Error: " + errorBuffer.ToString(), null);
            }
            return handle;
        }

        public PacketTotalStatistics GetTotalStatistics(PcapHandle pcapDescriptor)
        {
            var stat = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PcapUnmanagedStructures.pcap_stat_unix)));
            try
            {
                var result = pcap_stats(pcapDescriptor, stat);
                if (result != 0)
                {
                    PcapError.ThrowInvalidOperation("Failed getting total statistics", pcapDescriptor);
                }

                var managedStat = (PcapUnmanagedStructures.pcap_stat_unix)Marshal.PtrToStructure(stat, typeof(PcapUnmanagedStructures.pcap_stat_unix));
                return new PacketTotalStatistics(managedStat);
            }
            finally
            {
                Marshal.FreeHGlobal(stat);
            }
        }

        public int pcap_activate(PcapHandle p)
        {
            return SafeNativeMethods.pcap_activate(p);
        }

        public int pcap_breakloop(PcapHandle p)
        {
            return SafeNativeMethods.pcap_breakloop(p);
        }

        public void pcap_close(IntPtr adaptHandle)
        {
            SafeNativeMethods.pcap_close(adaptHandle);
        }

        public int pcap_compile(PcapHandle adaptHandle, IntPtr fp, string str, int optimize, uint netmask)
        {
            return SafeNativeMethods.pcap_compile(adaptHandle, fp, str, optimize, netmask);
        }

        public PcapHandle pcap_create(string dev, StringBuilder errbuf)
        {
            return SafeNativeMethods.pcap_create(dev, errbuf);
        }

        public int pcap_datalink(PcapHandle adaptHandle)
        {
            return SafeNativeMethods.pcap_datalink(adaptHandle);
        }

        public int pcap_datalink_name_to_val(string name)
        {
            return SafeNativeMethods.pcap_datalink_name_to_val(name);
        }

        public string pcap_datalink_val_to_description(int dlt)
        {
            return SafeNativeMethods.pcap_datalink_val_to_description(dlt);
        }

        public string pcap_datalink_val_to_description_or_dlt(int dlt)
        {
            return SafeNativeMethods.pcap_datalink_val_to_description_or_dlt(dlt);
        }

        public string pcap_datalink_val_to_name(int dlt)
        {
            return SafeNativeMethods.pcap_datalink_val_to_name(dlt);
        }

        public int pcap_dispatch(PcapHandle adaptHandle, int count, pcap_handler callback, IntPtr ptr)
        {
            return SafeNativeMethods.pcap_dispatch(adaptHandle, count, callback, ptr);
        }

        public void pcap_dump(IntPtr user, IntPtr h, IntPtr sp)
        {
            SafeNativeMethods.pcap_dump(user, h, sp);
        }

        public void pcap_dump_close(IntPtr p)
        {
            SafeNativeMethods.pcap_dump_close(p);
        }

        public IntPtr pcap_dump_file(IntPtr p)
        {
            return SafeNativeMethods.pcap_dump_file(p);
        }

        public int pcap_dump_flush(IntPtr p)
        {
            return SafeNativeMethods.pcap_dump_flush(p);
        }

        public long pcap_dump_ftell(IntPtr /* pcap_dumper_t* */ pcapDumper)
        {
            return SafeNativeMethods.pcap_dump_ftell(pcapDumper);
        }

        public IntPtr pcap_dump_open(PcapHandle adaptHandle, string fname)
        {
            return SafeNativeMethods.pcap_dump_open(adaptHandle, fname);
        }

        public int pcap_fileno(PcapHandle adapter)
        {
            return SafeNativeMethods.pcap_fileno(adapter);
        }

        public int pcap_findalldevs(ref PcapInterfaceHandle alldevs, StringBuilder errbuf)
        {
            return SafeNativeMethods.pcap_findalldevs(ref alldevs, errbuf);
        }

        public void pcap_freealldevs(IntPtr alldevs)
        {
            SafeNativeMethods.pcap_freealldevs(alldevs);
        }

        public void pcap_freecode(IntPtr fp)
        {
            SafeNativeMethods.pcap_freecode(fp);
        }

        public string pcap_geterr(PcapHandle adaptHandle)
        {
            return SafeNativeMethods.pcap_geterr(adaptHandle);
        }

        public int pcap_getnonblock(PcapHandle adaptHandle, StringBuilder errbuf)
        {
            return SafeNativeMethods.pcap_getnonblock(adaptHandle, errbuf);
        }

        public int pcap_get_selectable_fd(PcapHandle adaptHandle)
        {
            return SafeNativeMethods.pcap_get_selectable_fd(adaptHandle);
        }

        public string pcap_lib_version()
        {
            return SafeNativeMethods.pcap_lib_version();
        }

        public int pcap_next_ex(PcapHandle adaptHandle, ref IntPtr header, ref IntPtr data)
        {
            return SafeNativeMethods.pcap_next_ex(adaptHandle, ref header, ref data);
        }

        public int pcap_offline_filter(IntPtr prog, IntPtr header, IntPtr pkt_data)
        {
            return SafeNativeMethods.pcap_offline_filter(prog, header, pkt_data);
        }

        public PcapHandle pcap_open(string dev, int packetLen, int flags, int read_timeout, ref pcap_rmtauth rmtauth, StringBuilder errbuf)
        {
            return SafeNativeMethods.pcap_open(dev, packetLen, flags, read_timeout, ref rmtauth, errbuf);
        }

        public PcapHandle pcap_open_dead(int linktype, int snaplen)
        {
            return SafeNativeMethods.pcap_open_dead(linktype, snaplen);
        }

        public PcapHandle pcap_open_offline(string fname, StringBuilder errbuf)
        {
            return SafeNativeMethods.pcap_open_offline(fname, errbuf);
        }

        public int pcap_sendpacket(PcapHandle adaptHandle, IntPtr data, int size)
        {
            return SafeNativeMethods.pcap_sendpacket(adaptHandle, data, size);
        }

        public int pcap_setfilter(PcapHandle adaptHandle, IntPtr fp)
        {
            return SafeNativeMethods.pcap_setfilter(adaptHandle, fp);
        }

        public int pcap_setnonblock(PcapHandle adaptHandle, int nonblock, StringBuilder errbuf)
        {
            return SafeNativeMethods.pcap_setnonblock(adaptHandle, nonblock, errbuf);
        }

        public int pcap_set_buffer_size(PcapHandle adapter, int bufferSizeInBytes)
        {
            return SafeNativeMethods.pcap_set_buffer_size(adapter, bufferSizeInBytes);
        }

        public int pcap_set_promisc(PcapHandle p, int promisc)
        {
            return SafeNativeMethods.pcap_set_promisc(p, promisc);
        }

        public int pcap_set_rfmon(PcapHandle p, int rfmon)
        {
            return SafeNativeMethods.pcap_set_rfmon(p, rfmon);
        }

        public int pcap_set_snaplen(PcapHandle p, int snaplen)
        {
            return SafeNativeMethods.pcap_set_snaplen(p, snaplen);
        }

        public int pcap_set_timeout(PcapHandle p, int to_ms)
        {
            return SafeNativeMethods.pcap_set_timeout(p, to_ms);
        }

        public int pcap_snapshot(PcapHandle adapter)
        {
            return SafeNativeMethods.pcap_snapshot(adapter);
        }

        public int pcap_stats(PcapHandle adapter, IntPtr stat)
        {
            return SafeNativeMethods.pcap_stats(adapter, stat);
        }

        public int pcap_set_datalink(PcapHandle adaptHandle, int dlt)
        {
            throw new NotImplementedException();
        }

        public int pcap_list_datalinks(PcapHandle adaptHandle, ref IntPtr dataLinkList)
        {
            throw new NotImplementedException();
        }

        public void pcap_free_datalinks(IntPtr dataLinkList)
        {
            throw new NotImplementedException();
        }

        public int pcap_loop(PcapHandle adaptHandle, int count, pcap_handler callback, IntPtr ptr)
        {
            throw new NotImplementedException();
        }

        public int pcap_is_swapped(PcapHandle adapter)
        {
            throw new NotImplementedException();
        }

        public int pcap_major_version(PcapHandle adapter)
        {
            throw new NotImplementedException();
        }

        public int pcap_minor_version(PcapHandle adapter)
        {
            throw new NotImplementedException();
        }

        public int pcap_setmode(PcapHandle adapter, PacketCommunicatorMode mode)
        {
            throw new NotImplementedException();
        }

        public int pcap_setbuff(PcapHandle adapter, int dim)
        {
            throw new NotImplementedException();
        }

        public int pcap_setmintocopy(PcapHandle adapter, int size)
        {
            throw new NotImplementedException();
        }

        public IntPtr pcap_setsampling(PcapHandle adapter)
        {
            throw new NotImplementedException();
        }

        public int pcap_sendqueue_transmit(PcapHandle p, ref pcap_send_queue queue, int sync)
        {
            throw new PlatformNotSupportedException();
        }

        /// <summary>
        /// Per http://msdn.microsoft.com/en-us/ms182161.aspx 
        /// </summary>
        [SuppressUnmanagedCodeSecurity]
        private static class SafeNativeMethods
        {
            // NOTE: For mono users on non-windows platforms a .config file is used to map
            //       the windows dll name to the unix/mac library name
            //       This file is called $assembly_name.dll.config and is placed in the
            //       same directory as the assembly
            //       See http://www.mono-project.com/Interop_with_Native_Libraries#Library_Names
            private const string PCAP_DLL = "libpcap";

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_findalldevs(
                ref PcapInterfaceHandle /* pcap_if_t** */ alldevs,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] StringBuilder /* char* */ errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_freealldevs(IntPtr /* pcap_if_t* */ alldevs);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static PcapHandle /* pcap_t* */ pcap_open(
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string dev,
                int packetLen,
                int flags,
                int read_timeout,
                ref pcap_rmtauth rmtauth,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] StringBuilder errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static PcapHandle /* pcap_t* */ pcap_create(
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string dev,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] StringBuilder errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static PcapHandle /* pcap_t* */ pcap_open_offline(
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string/*const char* */ fname,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] StringBuilder/* char* */ errbuf);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static PcapHandle /* pcap_t* */ pcap_open_dead(int linktype, int snaplen);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_buffer_size(PcapHandle /* pcap_t */ adapter, int bufferSizeInBytes);

            /// <summary>Open a file to write packets. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static IntPtr /*pcap_dumper_t * */ pcap_dump_open(
                PcapHandle /*pcap_t * */adaptHandle,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string /*const char * */fname);

            /// <summary>
            ///  Save a packet to disk.  
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_dump(IntPtr /*u_char * */user, IntPtr /*const struct pcap_pkthdr * */h, IntPtr /*const u_char * */sp);

            /// <summary> close the files associated with p and deallocates resources.</summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_close(IntPtr /*pcap_t* */adaptHandle);

            /// <summary>
            /// To avoid callback, this returns one packet at a time
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_next_ex(PcapHandle /* pcap_t* */ adaptHandle, ref IntPtr /* **pkt_header */ header, ref IntPtr data);

            /// <summary>
            /// Send a raw packet.<br/>
            /// This function allows to send a raw packet to the network. 
            /// The MAC CRC doesn't need to be included, because it is transparently calculated
            ///  and added by the network interface driver.
            /// </summary>
            /// <param name="adaptHandle">the interface that will be used to send the packet</param>
            /// <param name="data">contains the data of the packet to send (including the various protocol headers)</param>
            /// <param name="size">the dimension of the buffer pointed by data</param>
            /// <returns>0 if the packet is succesfully sent, -1 otherwise.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_sendpacket(PcapHandle /* pcap_t* */ adaptHandle, IntPtr data, int size);

            /// <summary>
            /// Compile a packet filter, converting an high level filtering expression (see Filtering expression syntax) in a program that can be interpreted by the kernel-level filtering engine. 
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_compile(
                PcapHandle /* pcap_t* */ adaptHandle,
                IntPtr /*bpf_program **/fp,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string /*char * */str,
                int optimize,
                UInt32 netmask);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_setfilter(PcapHandle /* pcap_t* */ adaptHandle, IntPtr /*bpf_program **/fp);

            /// <summary>
            /// Returns if a given filter applies to an offline packet. 
            /// </summary>
            /// <returns></returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_offline_filter(IntPtr /*bpf_program **/ prog, IntPtr /* pcap_pkthdr* */ header, IntPtr pkt_data);

            /// <summary>
            /// Free up allocated memory pointed to by a bpf_program struct generated by pcap_compile()
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_freecode(IntPtr /*bpf_program **/fp);

            /// <summary>
            /// return the error text pertaining to the last pcap library error.
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string pcap_geterr(PcapHandle /*pcap_t * */ adaptHandle);

            /// <summary>Returns a pointer to a string giving information about the version of the libpcap library being used; note that it contains more information than just a version number. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string /*const char **/  pcap_lib_version();

            /// <summary>return the standard I/O stream of the 'savefile' opened by pcap_dump_open().</summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static IntPtr /*FILE **/  pcap_dump_file(IntPtr /*pcap_dumper_t **/p);

            /// <summary>Flushes the output buffer to the 'savefile', so that any packets 
            /// written with pcap_dump() but not yet written to the 'savefile' will be written. 
            /// -1 is returned on error, 0 on success. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_dump_flush(IntPtr /*pcap_dumper_t **/p);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static long pcap_dump_ftell(IntPtr /*pcap_dumper_t **/ pcapDumper);

            /// <summary>Closes a savefile. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static void pcap_dump_close(IntPtr /*pcap_dumper_t **/p);

            /// <summary> Return the link layer of an adapter. </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_datalink(PcapHandle /* pcap_t* */ adaptHandle);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_datalink_name_to_val(
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] string /* const char* */ name);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string pcap_datalink_val_to_description(int dlt);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string pcap_datalink_val_to_description_or_dlt(int dlt);

            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler), MarshalCookie = PcapStringMarshaler.Cookie)]
            internal extern static string pcap_datalink_val_to_name(int dlt);

            /// <summary>
            /// Set nonblocking mode. pcap_loop() and pcap_next() doesnt work in  nonblocking mode!
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_setnonblock(
                PcapHandle /* pcap_if_t** */ adaptHandle,
                int nonblock,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] StringBuilder /* char* */ errbuf);

            /// <summary>
            /// Get nonblocking mode, returns allways 0 for savefiles.
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_getnonblock(
                PcapHandle /* pcap_if_t** */ adaptHandle,
                [MarshalAs(UnmanagedType.CustomMarshaler, MarshalTypeRef = typeof(PcapStringMarshaler))] StringBuilder /* char* */ errbuf);

            /// <summary>
            /// Read packets until cnt packets are processed or an error occurs.
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_dispatch(PcapHandle /* pcap_t* */ adaptHandle, int count, PcapUnmanagedStructures.pcap_handler callback, IntPtr ptr);

            /// <summary>
            /// Retrieves a selectable file descriptor
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_get_selectable_fd(PcapHandle /* pcap_t* */ adaptHandle);

            /// <summary>
            /// Fills in the pcap_stat structure passed to the function
            /// based on the pcap_t adapter
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_stats(PcapHandle /* pcap_t* */ adapter, IntPtr /* struct pcap_stat* */ stat);

            /// <summary>
            /// Returns the snapshot length
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_snapshot(PcapHandle /* pcap_t... */ adapter);

            /// <summary>
            /// pcap_set_rfmon() sets whether monitor mode should be set on a capture handle when the handle is activated.
            /// If rfmon is non-zero, monitor mode will be set, otherwise it will not be set.  
            /// </summary>
            /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_rfmon(PcapHandle /* pcap_t* */ p, int rfmon);

            /// <summary>
            /// pcap_set_snaplen() sets the snapshot length to be used on a capture handle when the handle is activated to snaplen.  
            /// </summary>
            /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_snaplen(PcapHandle /* pcap_t* */ p, int snaplen);

            /// <summary>
            /// pcap_set_promisc() sets whether promiscuous mode should be set on a capture handle when the handle is activated. 
            /// If promisc is non-zero, promiscuous mode will be set, otherwise it will not be set.  
            /// </summary>
            /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_promisc(PcapHandle /* pcap_t* */ p, int promisc);

            /// <summary>
            /// pcap_set_timeout() sets the packet buffer timeout that will be used on a capture handle when the handle is activated to to_ms, which is in units of milliseconds.
            /// </summary>
            /// <returns>Returns 0 on success or PCAP_ERROR_ACTIVATED if called on a capture handle that has been activated.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_set_timeout(PcapHandle /* pcap_t* */ p, int to_ms);

            /// <summary>
            /// pcap_activate() is used to activate a packet capture handle to look at packets on the network, with the options that were set on the handle being in effect.  
            /// </summary>
            /// <returns>Returns 0 on success without warnings, a non-zero positive value on success with warnings, and a negative value on error. A non-zero return value indicates what warning or error condition occurred.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_activate(PcapHandle /* pcap_t* */ p);

            /// <summary>
            /// Force a pcap_dispatch() or pcap_loop() call to return
            /// </summary>
            /// <returns>Returns 0 on success without warnings, a non-zero positive value on success with warnings, and a negative value on error. A non-zero return value indicates what warning or error condition occurred.</returns>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_breakloop(PcapHandle /* pcap_t* */ p);

            #region libpcap specific
            /// <summary>
            /// Returns the file descriptor number from which captured packets are read,
            /// if a network device was opened with pcap_create() and pcap_activate() or
            /// with pcap_open_live(), or -1, if a ``savefile'' was opened with
            /// pcap_open_offline()
            /// Libpcap specific method
            /// </summary>
            [DllImport(PCAP_DLL, CallingConvention = CallingConvention.Cdecl)]
            internal extern static int pcap_fileno(PcapHandle /* pcap_t* p */ adapter);
            #endregion
        }
    }
}