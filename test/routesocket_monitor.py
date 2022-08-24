#!/usr/local/bin/python3

# Not really a test case, but a PoC for getting notified about changes in
# network addreses on FreeBSD using route sockets.

import socket
import struct
import ctypes.util

# from sys/net/route.h
RTM_NEWADDR = 0xC
RTM_DELADDR = 0xD
RTM_IFINFO = 0xE

RTA_IFA = 0x20

# from sys/socket.h
CTL_NET = 4
NET_RT_IFLIST = 3

# from sys/net/if.h
IFF_LOOPBACK = 0x8
IFF_MULTICAST = 0x800

SA_ALIGNTO = ctypes.sizeof(ctypes.c_long)

# global
link_blacklist = []


def parse_route_socket_response(buf, keep_link):
    offset = 0

    link = None
    print(len(buf))
    while offset < len(buf):
        # mask(addrs) has same offset in if_msghdr and ifs_msghdr
        rtm_len, _, rtm_type, addr_mask, flags = struct.unpack_from(
            '@HBBii', buf, offset)

        msg_type = ''
        if rtm_type not in [RTM_NEWADDR, RTM_DELADDR, RTM_IFINFO]:
            offset += rtm_len
            continue

        # those offset may unfortunately be architecture dependent
        # (152 is FreeBSD-specific)
        sa_offset = offset + ((16 + 152) if rtm_type == RTM_IFINFO else 20)

        if rtm_type in [RTM_NEWADDR, RTM_IFINFO]:
            msg_type = 'NEW'
        elif rtm_type == RTM_DELADDR:
            msg_type = 'DEL'

        # For a route socket message, and different to a sysctl response, the
        # link info is stored inside the same rtm message, so it has to
        # survive multiple rtm messages in such cases
        if not keep_link:
            link = None

        addr_type_idx = 1
        addr = None
        while sa_offset < offset + rtm_len:
            while (not (addr_type_idx & addr_mask)
                   and (addr_type_idx <= addr_mask)):
                addr_type_idx = addr_type_idx << 1

            sa_len, sa_fam = struct.unpack_from('@BB', buf, sa_offset)
            if (sa_fam in [socket.AF_INET, socket.AF_INET6]
               and addr_type_idx == RTA_IFA):
                addr_offset = 4 if sa_fam == socket.AF_INET else 8
                addr_length = 16 if sa_fam == socket.AF_INET6 else 4
                addr = socket.inet_ntop(sa_fam, buf[(sa_offset + addr_offset):(
                    sa_offset + addr_offset + addr_length)])
            elif sa_fam == socket.AF_LINK:
                if_idx, if_type, name_len = struct.unpack_from(
                    '@HBB', buf, sa_offset + 2)
                if if_idx > 0:
                    name_start = sa_offset + 8
                    name = (buf[name_start:name_start + name_len]).decode()
                    link = '{} {}'.format(name, if_idx)
                else:
                    link = 'system link'

            jump = (((sa_len + SA_ALIGNTO - 1) // SA_ALIGNTO) * SA_ALIGNTO
                    if sa_len > 0 else SA_ALIGNTO)
            sa_offset += jump
            addr_type_idx = addr_type_idx << 1

        if link is not None and rtm_type == RTM_IFINFO and (
                (flags & IFF_LOOPBACK) or not (flags & IFF_MULTICAST)):
            link_blacklist.append(link)

        if (link is not None and link not in link_blacklist) and (
                addr is not None):
            print('{} addr on interface {}: {}'.format(msg_type, link, addr))

        offset += rtm_len


mib = [CTL_NET, socket.AF_ROUTE, 0, 0, NET_RT_IFLIST, 0]
rt_mib = (ctypes.c_int * len(mib))()
rt_mib[:] = mib[:]

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
rt_size = ctypes.c_size_t()
r = libc.sysctl(ctypes.byref(rt_mib), ctypes.c_size_t(len(rt_mib)), 0,
                ctypes.byref(rt_size), 0, 0)
if r:
    print('unable to fetch routing table data')

rt_buf = ctypes.create_string_buffer(rt_size.value)
r = libc.sysctl(ctypes.byref(rt_mib), ctypes.c_size_t(len(rt_mib)), rt_buf,
                ctypes.byref(rt_size), 0, 0)
if r:
    print('unable to fetch routing table data')

parse_route_socket_response(rt_buf.raw, True)

# get further notifications from the kernel
s = socket.socket(socket.AF_ROUTE, socket.SOCK_RAW, socket.AF_UNSPEC)

while True:
    buf = s.recv(4096)
    parse_route_socket_response(buf, False)
