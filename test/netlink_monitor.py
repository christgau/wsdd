#!/usr/bin/python3

# Not really a test case, but a PoC for getting notified about changes in
# network addreses on Linux using netlink sockets.

import os
import socket
import struct

# from rtnetlink.h
RTMGRP_LINK = 1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV6_IFADDR = 0x100

RTM_NEWADDR = 20
RTM_DELADDR = 21
RTM_GETADDR = 22

# from netlink.h
NLM_F_REQUEST = 0x01

NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

# from if_addr.h
IFA_ADDRESS = 1
IFA_LOCAL = 2
IFA_LABEL = 3
IFA_FLAGS = 8

# self_defines

NLM_HDR_LEN = 16
NLM_HDR_ALIGNTO = 4

IFA_MSG_LEN = 8

# hardcoded as 4 in rtnetlink.h
RTA_ALIGNTO = 4

s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
s.bind((os.getpid(), RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR))

kernel = (0, 0)
req = struct.pack('@IHHIIB', NLM_HDR_LEN + 1, RTM_GETADDR, NLM_F_REQUEST |
                  NLM_F_DUMP, 1, os.getpid(), socket.AF_PACKET)

s.sendto(req, kernel)

while True:
    buf, src = s.recvfrom(4096)

    offset = 0
    while offset < len(buf):
        (h_len, h_type, h_flags, _, _) = struct.unpack_from(
            '@IHHII', buf, offset)

        msg_len = h_len - NLM_HDR_LEN
        if msg_len < 0:
            # print('invalid message size')
            break

        if h_type != RTM_NEWADDR and h_type != RTM_DELADDR:
            offset += ((msg_len + 1) // NLM_HDR_ALIGNTO) * NLM_HDR_ALIGNTO
            # print('not interested in message type ', h_type)
            # print('new offset: ', offset)
            continue

        offset += NLM_HDR_LEN
        # decode ifaddrmsg as in rtnetlink.h
        ifa_family, _, ifa_flags, ifa_scope, ifa_idx = struct.unpack_from(
                '@BBBBI', buf, offset)

        ifa_name = ''
        addr = ''
        # look for some details in attributes
        i = offset + IFA_MSG_LEN
        while i - offset < msg_len:
            attr_len, attr_type = struct.unpack_from('HH', buf, i)
            if attr_type == IFA_LABEL:
                ifa_name, = struct.unpack_from(str(attr_len - 4 - 1) + 's',
                                               buf, i + 4)
            elif attr_type == IFA_LOCAL and ifa_family == socket.AF_INET:
                b = buf[i + 4:i + 4 + 4]
                addr = socket.inet_ntop(socket.AF_INET, b)
            elif attr_type == IFA_ADDRESS and ifa_family == socket.AF_INET6:
                b = buf[i + 4:i + 4 + 16]
                addr = socket.inet_ntop(socket.AF_INET6, b)
            elif attr_type == IFA_FLAGS:
                _, ifa_flags = struct.unpack_from('HI', buf, i)
            i += ((attr_len + 1) // RTA_ALIGNTO) * RTA_ALIGNTO

        msg_type = 'NEW' if h_type == RTM_NEWADDR else 'DEL'
        print('{} addr on interface {} {} [{}]: {}'.format(msg_type, ifa_name,
              ifa_idx, hex(ifa_flags), addr))

        offset += ((msg_len + 1) // NLM_HDR_ALIGNTO) * NLM_HDR_ALIGNTO
