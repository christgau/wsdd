#!/usr/bin/env python3

# Implements a target service according to the Web Service Discovery
# specification.
#
# The purpose is to enable non-Windows devices to be found by the 'Network
# (Neighborhood)' from Windows machines.
#
# see http://specs.xmlsoap.org/ws/2005/04/discovery/ws-discovery.pdf and
# related documents for details (look at README for more references)
#
# (c) Steffen Christgau, 2017

import sys
import signal
import socket
import selectors
import struct
import argparse
import uuid
import time
import random
import logging
import platform
import ctypes.util
import collections
import xml.etree.ElementTree as ElementTree
import http.server


# sockaddr C type, with a larger data field to capture IPv6 addresses
# unfortunately, the structures differ on Linux and FreeBSD
if platform.system() == 'Linux':
    class sockaddr(ctypes.Structure):
        _fields_ = [('family', ctypes.c_uint16),
                    ('data', ctypes.c_uint8 * 24)]
else:
    class sockaddr(ctypes.Structure):
        _fields_ = [('length', ctypes.c_uint8),
                    ('family', ctypes.c_uint8),
                    ('data', ctypes.c_uint8 * 24)]


class if_addrs(ctypes.Structure):
    pass


if_addrs._fields_ = [('next', ctypes.POINTER(if_addrs)),
                     ('name', ctypes.c_char_p),
                     ('flags', ctypes.c_uint),
                     ('addr', ctypes.POINTER(sockaddr)),
                     ('netmask', ctypes.POINTER(sockaddr))]


class HTTPv6Server(http.server.HTTPServer):
    """Simple HTTP server with IPv6 support"""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


class MulticastInterface:
    """
    A class for handling multicast traffic on a given interface for a
    given address family. It provides multicast sender and receiver sockets
    """
    def __init__(self, family, address, intf_name):
        self.address = address
        self.family = family
        self.interface = intf_name
        self.recv_socket = socket.socket(self.family, socket.SOCK_DGRAM)
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.send_socket = socket.socket(self.family, socket.SOCK_DGRAM)
        self.transport_address = address
        self.multicast_address = None
        self.listen_address = None

        if family == socket.AF_INET:
            self.init_v4()
        elif family == socket.AF_INET6:
            self.init_v6()

        logger.info('joined multicast group {0} on {2}%{1}'.format(
            self.multicast_address, self.interface, self.address))
        logger.debug('transport address on {0} is {1}'.format(
            self.interface, self.transport_address))
        logger.debug('will listen for HTTP traffic on address {0}'.format(
            self.listen_address))

    def init_v6(self):
        idx = socket.if_nametoindex(self.interface)
        self.multicast_address = (WSD_MCAST_GRP_V6, WSD_UDP_PORT, 0x575C, idx)

        # v6: member_request = { multicast_addr, intf_idx }
        mreq = (
            socket.inet_pton(self.family, WSD_MCAST_GRP_V6) +
            struct.pack('@I', idx))
        self.recv_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        self.recv_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.recv_socket.bind((WSD_MCAST_GRP_V6, WSD_UDP_PORT))

        # bind to network interface, i.e. scope
        self.send_socket.bind(('::', 0, 0, idx))
        self.send_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        self.send_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, args.hoplimit)
        self.send_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)

        self.transport_address = '[{0}]'.format(self.address)
        self.listen_address = (self.address, WSD_HTTP_PORT, 0, idx)

    def init_v4(self):
        idx = socket.if_nametoindex(self.interface)
        self.multicast_address = (WSD_MCAST_GRP_V4, WSD_UDP_PORT)

        # v4: member_request (ip_mreqn) = { multicast_addr, intf_addr, idx }
        mreq = (
            socket.inet_pton(self.family, WSD_MCAST_GRP_V4) +
            socket.inet_pton(self.family, self.address) +
            struct.pack('@I', idx))

        self.recv_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self.recv_socket.bind((WSD_MCAST_GRP_V4, WSD_UDP_PORT))

        self.send_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
        self.send_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        self.send_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.hoplimit)

        self.listen_address = (self.address, WSD_HTTP_PORT)


# constants for WSD XML/SOAP parsing
WSA_URI = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'
WSD_URI = 'http://schemas.xmlsoap.org/ws/2005/04/discovery'
WSDP_URI = 'http://schemas.xmlsoap.org/ws/2006/02/devprof'

namespaces = {
    'soap': 'http://www.w3.org/2003/05/soap-envelope',
    'wsa': WSA_URI,
    'wsd': WSD_URI,
    'wsx': 'http://schemas.xmlsoap.org/ws/2004/09/mex',
    'wsdp': WSDP_URI,
    'pnpx': 'http://schemas.microsoft.com/windows/pnpx/2005/10',
    'pub': 'http://schemas.microsoft.com/windows/pub/2005/07'
}

WSD_MAX_KNOWN_MESSAGES = 10

WSD_PROBE = WSD_URI + '/Probe'
WSD_PROBE_MATCH = WSD_URI + '/ProbeMatches'
WSD_RESOLVE = WSD_URI + '/Resolve'
WSD_RESOLVE_MATCH = WSD_URI + '/ResolveMatches'
WSD_HELLO = WSD_URI + '/Hello'
WSD_BYE = WSD_URI + '/Bye'
WSD_GET = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get'
WSD_GET_RESPONSE = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse'

WSD_TYPE_DEVICE = 'wsdp:Device'
PUB_COMPUTER = 'pub:Computer'
WSD_TYPE_DEVICE_COMPUTER = '{0} {1}'.format(WSD_TYPE_DEVICE, PUB_COMPUTER)

WSD_MCAST_GRP_V4 = '239.255.255.250'
WSD_MCAST_GRP_V6 = 'ff02::c'  # link-local

WSA_ANON = WSA_URI + '/role/anonymous'
WSA_DISCOVERY = 'urn:schemas-xmlsoap-org:ws:2005:04:discovery'

# protocol assignments (WSD spec/Section 2.4)
WSD_UDP_PORT = 3702
WSD_HTTP_PORT = 5357
WSD_MAX_LEN = 32767

# SOAP/UDP transmission constants
MULTICAST_UDP_REPEAT = 4
UNICAST_UDP_REPEAT = 2
UDP_MIN_DELAY = 50
UDP_MAX_DELAY = 250
UDP_UPPER_DELAY = 500

# some globals
wsd_known_messages = collections.deque([])
wsd_message_number = 1
wsd_instance_id = int(time.time())
send_queue = []

args = None
logger = None


# shortcuts for building WSD responses
def wsd_add_metadata_version(parent):
    meta_data = ElementTree.SubElement(parent, 'wsd:MetadataVersion')
    meta_data.text = '1'


def wsd_add_types(parent):
    dev_type = ElementTree.SubElement(parent, 'wsd:Types')
    dev_type.text = WSD_TYPE_DEVICE_COMPUTER


def wsd_add_endpoint_reference(parent):
    endpoint = ElementTree.SubElement(parent, 'wsa:EndpointReference')
    address = ElementTree.SubElement(endpoint, 'wsa:Address')
    address.text = args.uuid.urn


def wsd_add_xaddr(parent, transport_addr):
    if transport_addr:
        item = ElementTree.SubElement(parent, 'wsd:XAddrs')
        item.text = 'http://{0}:{1}/{2}'.format(
            transport_addr, WSD_HTTP_PORT, args.uuid)


def wsd_build_message(to_addr, action_str, request_header, response):
    """
    Build a WSD message with a given action string including SOAP header.

    The message can be constructed based on a response to another
    message (given by its header) and with a optional response that
    serves as the message's body
    """
    global wsd_message_number

    env = ElementTree.Element('soap:Envelope')
    header = ElementTree.SubElement(env, 'soap:Header')

    to = ElementTree.SubElement(header, 'wsa:To')
    to.text = to_addr

    action = ElementTree.SubElement(header, 'wsa:Action')
    action.text = action_str

    msg_id = ElementTree.SubElement(header, 'wsa:MessageID')
    msg_id.text = uuid.uuid1().urn

    if request_header:
        req_msg_id = request_header.find('./wsa:MessageID', namespaces)
        if req_msg_id is not None:
            relates_to = ElementTree.SubElement(header, 'wsa:RelatesTo')
            relates_to.text = req_msg_id.text

    seq = ElementTree.SubElement(header, 'wsd:AppSequence', {
        'InstanceId': str(wsd_instance_id),
        'SequenceId': uuid.uuid1().urn,
        'MessageNumber': str(wsd_message_number)})
    wsd_message_number = wsd_message_number + 1

    body = ElementTree.SubElement(env, 'soap:Body')
    body.append(response)

    for prefix, uri in namespaces.items():
        env.attrib['xmlns:' + prefix] = uri

    xml = b'<?xml version="1.0" encoding="utf-8"?>'
    xml = xml + ElementTree.tostring(env, encoding='utf-8')

    logger.debug('constructed xml for WSD message: {0}'.format(xml))

    return xml


# WSD message type handling
def wsd_handle_probe(probe):
    types = probe.find('./wsd:Types', namespaces).text
    scopes = probe.find('./wsd:Scopes', namespaces)

    if scopes:
        # THINK: send fault message (see p. 21 in WSD)
        logger.warn('Scopes are not supported but were probed ({}).'.format(
            scopes))
        return None

    if not types == WSD_TYPE_DEVICE:
        logger.debug('unknown discovery type ({0}) during probe'.format(types))
        return None

    matches = ElementTree.Element('wsd:ProbeMatches')
    match = ElementTree.SubElement(matches, 'wsd:ProbeMatch')
    wsd_add_endpoint_reference(match)
    wsd_add_types(match)
    wsd_add_metadata_version(match)

    return matches


def wsd_handle_resolve(resolve, xaddr):
    addr = resolve.find('./wsa:EndpointReference/wsa:Address', namespaces)
    if addr is None:
        logger.debug('invalid resolve request: missing endpoint address')
        return None

    if not addr.text == args.uuid.urn:
        logger.debug(('invalid resolve request: address ({}) does not match '
                      'own one ({})').format(addr.text, args.uuid.urn))
        return None

    matches = ElementTree.Element('wsd:ResolveMatches')
    match = ElementTree.SubElement(matches, 'wsd:ResolveMatch')
    wsd_add_endpoint_reference(match)
    wsd_add_types(match)
    wsd_add_xaddr(match, xaddr)
    wsd_add_metadata_version(match)

    return matches


def wsd_handle_get():
    # see https://msdn.microsoft.com/en-us/library/hh441784.aspx for an example
    metadata = ElementTree.Element('wsx:Metadata')
    section = ElementTree.SubElement(metadata, 'wsx:MetadataSection', {
        'Dialect': WSDP_URI + '/ThisDevice'})
    device = ElementTree.SubElement(section, 'wsdp:ThisDevice')
    ElementTree.SubElement(device, 'wsdp:FriendlyName').text = (
            'WSD Device {0}'.format(args.hostname))
    ElementTree.SubElement(device, 'wsdp:FirmwareVersion').text = '1.0'
    ElementTree.SubElement(device, 'wsdp:SerialNumber').text = '1'

    section = ElementTree.SubElement(metadata, 'wsx:MetadataSection', {
        'Dialect': WSDP_URI + '/ThisModel'})
    model = ElementTree.SubElement(section, 'wsdp:ThisModel')
    ElementTree.SubElement(model, 'wsdp:Manufacturer').text = 'wsdd'
    ElementTree.SubElement(model, 'wsdp:ModelName').text = 'wsdd'
    ElementTree.SubElement(model, 'pnpx:DeviceCategory').text = 'Computers'

    section = ElementTree.SubElement(metadata, 'wsx:MetadataSection', {
        'Dialect': WSDP_URI + '/Relationship'})
    rel = ElementTree.SubElement(section, 'wsdp:Relationship', {
        'Type': WSDP_URI + '/host'})
    host = ElementTree.SubElement(rel, 'wsdp:Host')
    wsd_add_endpoint_reference(host)
    ElementTree.SubElement(host, 'wsdp:Types').text = PUB_COMPUTER
    ElementTree.SubElement(host, 'wsdp:ServiceId').text = args.uuid.urn
    if args.domain:
        ElementTree.SubElement(host, PUB_COMPUTER).text = (
                '{0}/Domain:{1}'.format(
                    args.hostname.upper(),
                    args.domain))
    else:
        ElementTree.SubElement(host, PUB_COMPUTER).text = (
                '{0}/Workgroup:{1}'.format(
                    args.hostname.upper(),
                    args.workgroup.upper()))

    return metadata


def wsd_is_duplicated_msg(msg_id):
    """
    Check for a duplicated message.

    Implements SOAP-over-UDP Appendix II Item 2
    """
    if msg_id in wsd_known_messages:
        return True

    wsd_known_messages.append(msg_id)
    if len(wsd_known_messages) > WSD_MAX_KNOWN_MESSAGES:
        wsd_known_messages.popleft()

    return False


def wsd_handle_message(data, interface):
    """
    handle a WSD message that might be received by a MulticastInterface class
    """
    tree = ElementTree.fromstring(data)
    header = tree.find('./soap:Header', namespaces)
    msg_id = header.find('./wsa:MessageID', namespaces).text

    # if message came over multicast interface, check for duplicates
    if interface and wsd_is_duplicated_msg(msg_id):
        logger.debug('known message ({0}): dropping it'.format(msg_id))
        return None

    response = None
    action = header.find('./wsa:Action', namespaces).text
    body = tree.find('./soap:Body', namespaces)

    logger.info('handling WSD {0} type message ({1})'.format(action, msg_id))
    logger.debug('incoming message content is {0}'.format(data))
    if action == WSD_PROBE:
        probe = body.find('./wsd:Probe', namespaces)
        response = wsd_handle_probe(probe)
        return wsd_build_message(WSA_ANON, WSD_PROBE_MATCH, header,
                                 response) if response else None
    elif action == WSD_RESOLVE:
        resolve = body.find('./wsd:Resolve', namespaces)
        response = wsd_handle_resolve(resolve, interface.transport_address)
        return wsd_build_message(WSA_ANON, WSD_RESOLVE_MATCH, header,
                                 response) if response else None
    elif action == WSD_GET:
        return wsd_build_message(
            WSA_ANON,
            WSD_GET_RESPONSE,
            header,
            wsd_handle_get())
    else:
        logger.debug('unhandled action {0}/{1}'.format(action, msg_id))
        return None


class WSDUdpRequestHandler():
    """Class for handling WSD requests coming from UDP datagrams."""
    def __init__(self, interface):
        self.interface = interface

    def handle_request(self):
        msg, address = self.interface.recv_socket.recvfrom(WSD_MAX_LEN)
        msg = wsd_handle_message(msg, self.interface)
        if msg:
            self.enqueue_datagram(msg, address=address)

    def send_hello(self):
        """WS-Discovery, Section 4.1, Hello message"""
        hello = ElementTree.Element('wsd:Hello')
        wsd_add_endpoint_reference(hello)
        # THINK: Microsoft does not send the transport address here due
        # to privacy reasons. Could make this optional.
        wsd_add_xaddr(hello, self.interface.transport_address)
        wsd_add_metadata_version(hello)

        msg = wsd_build_message(WSA_DISCOVERY, WSD_HELLO, None, hello)
        self.enqueue_datagram(msg, msg_type='Hello')

    def send_bye(self):
        """WS-Discovery, Section 4.2, Bye message"""
        bye = ElementTree.Element('wsd:Bye')
        wsd_add_endpoint_reference(bye)

        msg = wsd_build_message(WSA_DISCOVERY, WSD_BYE, None, bye)
        self.enqueue_datagram(msg, msg_type='Bye')

    def enqueue_datagram(self, msg, address=None, msg_type=None):
        """
        Add an outgoing WSD (SOAP) message to the queue of outstanding messages

        Implements SOAP over UDP, Appendix I.
        """
        if not address:
            address = self.interface.multicast_address

        if msg_type:
            logger.debug('scheduling {0} message via {1} to {2}'.format(
                msg_type, self.interface.interface, address))

        msg_count = (
            MULTICAST_UDP_REPEAT
            if address == self.interface.multicast_address
            else UNICAST_UDP_REPEAT)

        due_time = time.time()
        t = random.randint(UDP_MIN_DELAY, UDP_MAX_DELAY)
        for i in range(msg_count):
            send_queue.append([due_time, self.interface, address, msg])
            due_time += t / 1000
            t = min(t * 2, UDP_UPPER_DELAY)


class WSDHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    """Class for handling WSD requests coming over HTTP"""
    def log_message(self, fmt, *args):
        logger.info("{} - - ".format(self.address_string()) + fmt % args)

    def do_POST(s):
        if s.path != '/' + str(args.uuid):
            s.send_error(404)

        if s.headers['Content-Type'] != 'application/soap+xml':
            s.send_error(400, 'Invalid Content-Type')

        content_length = int(s.headers['Content-Length'])
        body = s.rfile.read(content_length)

        response = wsd_handle_message(body, None)
        if response:
            s.send_response(200)
            s.send_header('Content-Type', 'application/soap+xml')
            s.end_headers()
            s.wfile.write(response)
        else:
            s.send_error(500)


def enumerate_host_interfaces():
    """Get all addresses of all installed interfaces, except loopback"""
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    addr = ctypes.POINTER(if_addrs)()
    retval = libc.getifaddrs(ctypes.byref(addr))
    if retval:
        raise OSError(ctypes.get_errno())

    addrs = []
    ptr = addr
    while ptr:
        deref = ptr[0]
        family = deref.addr[0].family if deref.addr else None
        if family == socket.AF_INET:
            addrs.append((
                deref.name.decode(), family,
                socket.inet_ntop(family, bytes(deref.addr[0].data[2:6]))))
        elif family == socket.AF_INET6:
            if bytes(deref.addr[0].data[6:8]) == b'\xfe\x80':
                addrs.append((
                    deref.name.decode(), family,
                    socket.inet_ntop(family, bytes(deref.addr[0].data[6:22]))))

        ptr = deref.next

    libc.freeifaddrs(addr)

    # filter detected addresses by command line arguments,
    # always exclude 'lo' interface
    if args.ipv4only:
        addrs = [x for x in addrs if x[1] == socket.AF_INET]

    if args.ipv6only:
        addrs = [x for x in addrs if x[1] == socket.AF_INET6]

    addrs = [x for x in addrs if not x[0].startswith('lo')]
    if args.interface:
        addrs = [x for x in addrs if x[0] in args.interface]

    return addrs


def sigterm_handler(signum, frame):
    if signum == signal.SIGTERM:
        logger.info('received SIGTERM, tearing down')
        # implictely raise SystemExit to cleanup properly
        sys.exit(0)


def parse_args():
    global args, logger

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-i', '--interface',
        help='interface address to use',
        action='append', default=[])
    parser.add_argument(
        '-H', '--hoplimit',
        help='hop limit for multicast packets (default = 1)', type=int,
        default=1)
    parser.add_argument(
        '-u', '--uuid',
        help='UUID for the target device',
        default=None)
    parser.add_argument(
        '-v', '--verbose',
        help='increase verbosity',
        action='count', default=0)
    parser.add_argument(
        '-d', '--domain',
        help='set domain name (disables workgroup)',
        default=None)
    parser.add_argument(
        '-n', '--hostname',
        help='override (NetBIOS) hostname to be used (default hostname)',
        default=socket.gethostname())
    parser.add_argument(
        '-w', '--workgroup',
        help='set workgroup name (default WORKGROUP)',
        default='WORKGROUP')
    parser.add_argument(
        '-t', '--nohttp',
        help='disable http service (for debugging, e.g.)',
        action='store_true')
    parser.add_argument(
        '-4', '--ipv4only',
        help='use only IPv4 (default = off)',
        action='store_true')
    parser.add_argument(
        '-6', '--ipv6only',
        help='use IPv6 (default = off)',
        action='store_true')

    args = parser.parse_args(sys.argv[1:])

    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose > 1:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING

    logging.basicConfig(level=log_level, format=(
        '%(asctime)s:%(name)s %(levelname)s(pid %(process)d): %(message)s'))
    logger = logging.getLogger('wsdd')

    if not args.interface:
        logger.warning('no interface given, using all interfaces')

    if not args.uuid:
        args.uuid = uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname())
        logger.info('using pre-defined UUID {0}'.format(str(args.uuid)))
    else:
        args.uuid = uuid.UUID(args.uuid)
        logger.info('user-supplied device UUID is {0}'.format(str(args.uuid)))

    for prefix, uri in namespaces.items():
        ElementTree.register_namespace(prefix, uri)


def send_outstanding_messages(block=False):
    """
    Send all queued datagrams for which the timeout has been reached. If block
    is true then all queued messages will be sent but with their according
    delay.
    """
    if len(send_queue) == 0:
        return None

    # reverse ordering for faster removal of the last element
    send_queue.sort(key=lambda x: x[0], reverse=True)

    # Emit every message that is "too late". Note that in case the system
    # time jumps backward, multiple outstanding message which have a
    # delay between them are sent out without that delay.
    now = time.time()
    while len(send_queue) > 0 and (send_queue[-1][0] <= now or block):
        interface = send_queue[-1][1]
        addr = send_queue[-1][2]
        msg = send_queue[-1][3]
        try:
            interface.send_socket.sendto(msg, addr)
        except Exception as e:
            logger.error('error while sending packet on {}: {}'.format(
                interface.interface, e))

        del send_queue[-1]
        if block and len(send_queue) > 0:
            delay = send_queue[-1][0] - now
            if delay > 0:
                time.sleep(delay)
                now = time.time()

    if len(send_queue) > 0 and not block:
        return send_queue[-1][0] - now

    return None


def serve_wsd_requests(addresses):
    """
    Multicast handling: send Hello message on startup, receive from multicast
    sockets and handle the messages, and emit Bye message when process gets
    terminated by signal
    """
    s = selectors.DefaultSelector()
    udp_srvs = []

    for address in addresses:
        interface = MulticastInterface(address[1], address[2], address[0])
        udp_srv = WSDUdpRequestHandler(interface)
        udp_srvs.append(udp_srv)
        s.register(interface.recv_socket, selectors.EVENT_READ, udp_srv)

        if not args.nohttp:
            klass = (
                http.server.HTTPServer
                if interface.family == socket.AF_INET
                else HTTPv6Server)
            http_srv = klass(interface.listen_address, WSDHttpRequestHandler)
            s.register(http_srv.fileno(), selectors.EVENT_READ, http_srv)

    # everything is set up, announce ourself and serve requests
    try:
        for srv in udp_srvs:
            srv.send_hello()

        while True:
            try:
                timeout = send_outstanding_messages()
                events = s.select(timeout)
                for key, mask in events:
                    key.data.handle_request()
            except (SystemExit, KeyboardInterrupt):
                # silently exit the loop
                logger.debug('got termination signal')
                break
            except Exception:
                logger.exception('error in main loop')
    finally:
        logger.info('shutting down gracefully...')

    # say goodbye
    for srv in udp_srvs:
        srv.send_bye()

    send_outstanding_messages(True)


def main():
    parse_args()

    addresses = enumerate_host_interfaces()
    if not addresses:
        logger.error("No multicast addresses available. Exiting.")
        return 1

    signal.signal(signal.SIGTERM, sigterm_handler)
    serve_wsd_requests(addresses)
    logger.info('Done.')


if __name__ == '__main__':
    main()
