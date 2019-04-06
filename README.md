# wsdd

wsdd implements a Web Service Discovery host daemon. This enables (Samba)
hosts, like your local NAS device, to be found by Web Service Discovery Clients
like Windows.

# Purpose

Since NetBIOS discovery is not supported by Windows anymore, wsdd makes hosts
to appear in Windows again using the Web Service Discovery method. This is
beneficial for devices running Samba, like NAS or file sharing servers on your
local network.

## Background

With Windows 10 version 1511, support for SMBv1 and thus NetBIOS device discovery
was disabled by default.  Depending on the actual edition, later versions of
Windows starting from version 1709 ("Fall Creators Update") do not allow the
installation of the SMBv1 client anymore.  This causes hosts running Samba not
to be listed in the Explorer's "Network (Neighborhood)" views. While there is no
connectivity problem and Samba will still run fine, users might want to have
their Samba hosts to be listed by Windows automatically.

You may ask: What about Samba itself, shouldn't this functionality be included
in Samba!? Yes, maybe. However, using Samba as file sharing service is still
possible even if the host running Samba is not listed in the Network
Neighborhood. You can still connect using the host name (given that name
resolution works) or IP address. So you can have network drives and use shared
folders as well. In addition, there is a patch lurking around in the Samba
bug tracker since 2015. So it may happen that this feature gets integrated into
Samba at some time in the future.

# Requirements

wsdd requires Python 3 only. It runs on Linux and FreeBSD. Other Unixes, such
as OpenBSD or NetBSD, might work as well but were not tested.

Although Samba is not strictly required by wsdd itself, it makes sense to run
wsdd only on hosts with a running Samba daemon. Note that the OpenRC/Gentoo
init script depends on the Samba service.

# Installation and Usage

No installation steps are required. Just place the wsdd.py file anywhere you
want to, rename it to wsdd, and run it from there. The init scripts/unit files
assume that wsdd is installed under `/usr/bin/wsdd` or `/usr/local/bin/wsdd` in
case of FreeBSD. There are no configuration files. No special privileges are
required to run wsdd, so it is advisable to run the service as an unprivileged
user such as _nobody_.

The `etc` directory of the repo contains sample configuration files for
different init(1) systems, namely FreeBSD's rc.d, Gentoo's openrc, and systemd
which is used in most contemporary Linux distros. Those files may be used as
templates for their actual usage. They are likely to require adjustments to the
actual distribution/installation where they are to be used.

## Firewall Setup

Both incoming and outgoing multicast traffic on port 3702 must be allowed. For
IPv4, the multicast address is `239.255.255.250`, for IPv6 the link local SSDP
multicast address (`fe02::c`) is used.

Incoming TCP traffic (and related outgoing traffic) on port 5357 must be
allowed.

## Options

 * `-i INTERFACE`, `--interface INTERFACE`

     Specify on which interfaces wsdd will be listening on. If no interfaces are
     specified, all interfaces are used. The loop-back interface is never used,
     even when it was explicitly specified. For interfaces with IPv6 addresses,
     only link-local addresses will be used for announcing the host on the
     network. This option can be provided multiple times in order to use more
     than interface (but no all).

 * `-H HOPLIMIT`, `--hoplimit HOPLIMIT`

     Set the hop limit for multicast packets. The default is 1 which should
     prevent packets from leaving the local network segment.

 * `-u UUID`, `--uuid UUID`

     The WSD specification requires a device to have a unique address that is
     stable across reboots or changes in networks. In the context of the
     standard, it is assumed that this is something like a serial number. wsdd
     uses the UUID version 5 with the DNS namespace and the host name of the
     local machine as inputs. Thus, the host name should be stable and not be
     modified, e.g. by DHCP. However, if you want wsdd to use a specific UUID
     you can use this option.

 * `-d DOMAIN`, `--domain DOMAIN`

     Assume that the host running wsdd joined an ADS domain. This will make
     wsdd report the host being a domain member. It disables workgroup
     membership reporting.

 * `-n HOSTNAME`, `--hostname HOSTNAME`

     Override the host name wsdd uses during discovery. By default the machine's
     host name is used (look at hostname(1)). Only the host name part of a
     possible FQDN will be used in the default case.

 * `-w WORKGROUP`, `--workgroup WORKGROUP`

	 By default wsdd reports the host is a member of a workgroup rather than a
	 domain (use the -d/--domain option to override this). With -w/--workgroup
	 the default workgroup name can be changed. The default work group name is
	 WORKGROUP.

 * `-t`, `--nohttp`

     Do not service http requests of the WSD protocol. This option is intended
     for debugging purposes where another process may handle the Get messages.

 * `-v`, `--verbose`

     Additively increase verbosity of the log output. A single occurrence of
     -v/--verbose sets the log level to INFO. More -v options set the log level
     to DEBUG.

 * `-4`, `--ipv4only` (see below)
 * `-6`, `--ipv6only`

	 Restrict to the given address family. If both options are specified no
	 addreses will be available and wsdd will exit.

## Example Usage

 * handle traffic on eth0 only, but only with IPv6 addresses

    `wsdd -i eth0 -6`

    or

    `wsdd --interface eth0 --ipv6only`

 * set the Workgroup according to smb.conf and be verbose

    `SMB_GROUP=$(grep -i '^\s*workgroup\s*=' smb.conf | cut -f2 -d= | tr -d '[:blank:]')`

    `wsdd -v -w $SMB_GROUP`

## Technical Description

(Read the source for more details)

For each specified (or all) network interfaces, except for loopback, an UDP
multicast socket for message reception, an UDP send socket for replying
messages using unicast, and a listening TCP socket is created. This is done for
both the IPv4 and the IPv6 address family if not configured otherwise by the
command line arguments (see above). Upon startup a _Hello_ message is sent.
When wsdd terminates due to a SIGTERM signal or keyboard interrupt, a graceful
shutdown is performed by sending a _Bye_ message. I/O multiplexing is used to
handle network traffic of the different sockets within a single process.

# Known Issues

## Security

wsdd does not implement any security feature, e.g. by using TLS for the http
service. This is because wsdd's intended usage is within private, i.e. home,
LANs. The _Hello_ message contains the hosts transport address, i.e. the IP
address which speeds up discovery (avoids _Resolve_ message).

## Using only IPv6 on FreeBSD

If wsdd is running on FreeBSD using IPv6 only, the host running wsdd may not be
reliably discovered. The reason appears to be that Windows is not always able
to connect to the HTTP service for unknown reasons. As a workaround, run wsdd
with IPv4 only.

# Contributing

Contributions are welcome. Please ensure PEP8 compliance when submitting
patches or pull requests.

# Licence

The code is licensed under the [MIT license](https://opensource.org/licenses/MIT).

# Acknowledgements

Thanks to Jose M. Prieto and his colleague Tobias Waldvogel who wrote the
mentioned patch for Samba to provide WSD and LLMNR support. A look at their
patch set made cross-checking the WSD messages easier.

# References and Further Reading

## Technical Specification

 * [Web Services Dynamic Discovery](http://specs.xmlsoap.org/ws/2005/04/discovery/ws-discovery.pdf)

 * [SOAP-over-UDP (used during multicast)](http://specs.xmlsoap.org/ws/2004/09/soap-over-udp/soap-over-udp.pdf)

 * [MSDN Documentation on Publication Services Data Structure](https://msdn.microsoft.com/en-us/library/hh442048.aspx)

 * [MSDN on Windows WSD Compliance](https://msdn.microsoft.com/en-us/library/windows/desktop/bb736564.aspx)

 * ...and the standards referenced within the above.

## Documentation and Discussion on Windows/WSD

 * [Microsoft help entry on SMBv1 is not installed by default in Windows 10 Fall Creators Update and Windows Server, version 1709](https://support.microsoft.com/en-us/help/4034314/smbv1-is-not-installed-windows-10-and-windows-server-version-1709)

 * [Samba WSD and LLMNR support (Samba Bug #11473)](https://bugzilla.samba.org/show_bug.cgi?id=11473)

 * [Discussion at tenforums.com about missing hosts in network](https://www.tenforums.com/network-sharing/31221-windows-10-1511-network-browsing-issue.html)
   Note: Solutions suggest to go back to SMBv1 protocol which is deprecated! Do not follow this advice.

 * [Discussion in Synology Community Forum](https://forum.synology.com/enu/viewtopic.php?f=49&t=106924)

## Other stuff

 * Meanwhile, there is a [C implementation of a WSD daemon](https://github.com/Andy2244/wsdd2), named wsdd2.
   This one also includes LLMNR which wsdd lacks. However, LLMNR may not be required depending on the actual
   network/name resolution setup.

 * [OpenWRT includes](https://github.com/openwrt/packages/pull/5563) the above C implementation.
   So OpenWRT users are unlikely to need an installation of wsdd.

 * [FreeNAS](https://redmine.ixsystems.com/issues/72099) appears to have wsdd included in the distribution.
