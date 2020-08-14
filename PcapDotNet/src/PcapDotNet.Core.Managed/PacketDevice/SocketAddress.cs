using System;
using System.Collections.Generic;
using System.Text;

namespace PcapDotNet.Core
{
    /// <summary>
	/// The base of all device addresses.
	/// Contains the family (type) of the address.
	/// </summary>
    public abstract class SocketAddress
    {
        private SocketAddressFamily _family;

        protected SocketAddress(ushort family)
        {
            _family = (SocketAddressFamily)family;
        }

        /// <summary>
		/// Family (type) of the socket address.
		/// </summary>
        public SocketAddressFamily Family => _family;

        public override string ToString()
        {
            return Family.ToString();
        }
    }

}
