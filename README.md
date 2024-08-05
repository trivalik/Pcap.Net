# Pcap.Net
.NET wrapper for [Npcap](https://npcap.com/) (formerly WinPcap), written in C# using [P/Invoke](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke), providing almost all Npcap functions and including a package interpretation framework.

## Need help?
* See the [Pcap.Net wiki](https://github.com/PcapDotNet/Pcap.Net/wiki) for guides on using and developing Pcap.Net.
* Use the [Pcap.Net Q&A Group](https://groups.google.com/forum/#!forum/pcapdotnet) to ask questions.

## Features

### .NET wrapper for Npcap
Including:
* Getting the list of Live Devices on the local host.
* Reading packets from Live Devices (Network Devices) and Offline Devices (Files) using the different WinPcap methods.
* Receiving statistics on the entire capture.
* Receiving statistics of packets instead of the full packets.
* Using different sampling methods.
* Applying Berkley Packet Filters.
* Sending packets to Live Devices directly or using WinPcap's send queues.
* Dumping packets to Pcap files.
* Using Enumerables to receive packets (and LINQ).

Not including:
* AirPcap features.
* Remote Pcap features.

### Packet interpretation
* Ethernet + VLAN tagging (802.1Q)
* ARP
* IPv4
* IPv6
* GRE
* ICMP
* IGMP
* UDP
* TCP
* DNS
* HTTP

## (Possible) Roadmap/Goals

### v2.0
* Port v1.0 C++/CLI code to managed C# code.
* Support for use in a .NET Core or .NET 5+ project.
* Keep API as compatible as possible with v1.0.
* Create the ability to support platforms other than Windows.


### v3.0
* Merge into a single assembly (DLL). Possible as there is no longer a C++/CLI assembly.
* TBD

### Unix support
* Find good solution for `PacketSendBuffer`.