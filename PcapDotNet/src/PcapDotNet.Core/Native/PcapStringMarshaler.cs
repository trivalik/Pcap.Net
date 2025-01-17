﻿using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PcapDotNet.Core.Native
{
    // Taken from: sharppcap/SharpPcap/LibPcap/LibPcapSafeNativeMethods.Encoding.cs
    /// <summary>
    /// Helper class to marshall string depending on encoding used by Libpcap
    /// </summary>
    internal class PcapStringMarshaler : ICustomMarshaler
    {
        public const string Cookie = "no_free";

        public static ICustomMarshaler GetInstance(string cookie)
        {
            return new PcapStringMarshaler(cookie);
        }

        private readonly bool _freeOnClean;

        public PcapStringMarshaler(string cookie)
        {
            // If the string was not allocated by us, don't free it
            _freeOnClean = !cookie.Contains(Cookie);
        }

        public void CleanUpManagedData(object managedObj)
        {
            // Nothing to clean
        }

        public void CleanUpNativeData(IntPtr nativeData)
        {
            if (_freeOnClean)
            {
                Marshal.FreeHGlobal(nativeData);
            }
        }

        public int GetNativeDataSize()
        {
            return -1;
        }

        public IntPtr MarshalManagedToNative(object managedObj)
        {
            if (managedObj is null)
            {
                return IntPtr.Zero;
            }
            byte[] bytes = null;
            var byteCount = 0;
            if (managedObj is string str)
            {
                var endcoding = GetEncoding();
                bytes = endcoding.GetBytes(str);
                byteCount = bytes.Length + 1;
            }
            else if (managedObj is StringBuilder builder)
            {
                var endcoding = GetEncoding();
                bytes = endcoding.GetBytes(builder.ToString());
                byteCount = endcoding.GetMaxByteCount(builder.Capacity) + 1;
            }

            if (bytes is null)
            {
                throw new ArgumentException("The input argument is not a supported type.");
            }
            var ptr = Marshal.AllocHGlobal(byteCount);
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
            // Put zero string termination
            Marshal.WriteByte(ptr + bytes.Length, 0);
            return ptr;
        }

        public unsafe object MarshalNativeToManaged(IntPtr nativeData)
        {
            if (nativeData == IntPtr.Zero)
            {
                return null;
            }
            var bytes = (byte*)nativeData;
            var nbBytes = 0;
            while (*(bytes + nbBytes) != 0)
            {
                nbBytes++;
            }
            return GetEncoding().GetString(bytes, nbBytes);
        }

        private static Encoding GetEncoding()
        {
            // HACK: while init Interop (static ctor) PcapPal is mabybe null.
            // create the windows PAL pcap_init is called and we need encoding either way
            // whats a better solution here???
            return Interop.Pcap?.StringEncoding ?? Encoding.Default;
        }
    }
}
