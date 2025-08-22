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
# (c) Steffen Christgau, 2017-2025

import sys
import signal
import socket
import asyncio
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
import http
import http.server
import urllib.request
import urllib.parse
import os
import pwd
import grp
import datetime

from typing import Any, Callable, ClassVar, Deque, Dict, List, Optional, Set, Union, Tuple

# try to load more secure XML module first, fallback to default if not present
try:
    from defusedxml.ElementTree import fromstring as ETfromString
except ModuleNotFoundError:
    from xml.etree.ElementTree import fromstring as ETfromString

try:
    import systemd.daemon  # type: ignore
except ModuleNotFoundError:
    # Non-systemd host
    pass

WSDD_VERSION: str = '0.9'


args: argparse.Namespace
logger: logging.Logger


class NetworkInterface:

    _name: str
    _index: int
    _scope: int

    def __init__(self, name: str, scope: int, index: int) -> None:
        self._name = name
        self._scope = scope
        if index is not None:
            self._index = index
        else:
            self._index = socket.if_nametoindex(self._name)

    @property
    def name(self) -> str:
        return self._name

    @property
    def scope(self) -> int:
        return self._scope

    @property
    def index(self) -> int:
        return self._index

    def __str__(self) -> str:
        return self._name

    def __eq__(self, other) -> bool:
        return self._name == other.name


class NetworkAddress:

    _family: int
    _raw_address: bytes
    _address_str: str
    _interface: NetworkInterface

    def __init__(self, family: int, raw: Union[bytes, str], interface: NetworkInterface) -> None:
        self._family = family
        self._raw_address = raw if isinstance(raw, bytes) else socket.inet_pton(family, raw.partition('%')[0])
        self._interface = interface

        self._address_str = socket.inet_ntop(self._family, self._raw_address)

    @property
    def address_str(self):
        return self._address_str

    @property
    def family(self):
        return self._family

    @property
    def interface(self):
        return self._interface

    @property
    def is_multicastable(self):
        """ return true if the (interface) address can be used for creating (link-local) multicasting sockets  """
        # Nah, this check is not optimal but there are no local flags for
        # addresses, but it should be safe for IPv4 anyways
        # (https://tools.ietf.org/html/rfc5735#page-3)
        return ((self._family == socket.AF_INET) and (self._raw_address[0] != 127)
                or (self._family == socket.AF_INET6) and (self._raw_address[0:2] == b'\xfe\x80'))

    @property
    def raw(self):
        return self._raw_address

    @property
    def transport_str(self):
        """the string representation of the local address overridden in network setup (for IPv6)"""
        return self._address_str if self._family == socket.AF_INET else '[{}]'.format(self._address_str)

    def __str__(self) -> str:
        return '{}%{}'.format(self._address_str, self._interface.name)

    def __eq__(self, other) -> bool:
        return (self._family == other.family and self.raw == other.raw and self.interface == other.interface)


class UdpAddress(NetworkAddress):

    _transport_address: Tuple
    _port: int

    def __init__(self, family, transport_address: Tuple, interface: NetworkInterface) -> None:

        if not (family == socket.AF_INET or family == socket.AF_INET6):
            raise RuntimeError('Unsupport address address family: {}.'.format(family))

        self._transport_address = transport_address
        self._port = transport_address[1]

        super().__init__(family, transport_address[0], interface)

    @property
    def transport_address(self):
        return self._transport_address

    @property
    def port(self):
        return self._port

    def __eq__(self, other) -> bool:
        return self.transport_address == other.transport_address


class INetworkPacketHandler:

    def handle_packet(self, msg: str, udp_src_address: UdpAddress) -> None:
        pass


class MulticastHandler:
    """
    A class for handling multicast traffic on a given interface for a
    given address family. It provides multicast sender and receiver sockets
    """

    # base interface addressing information
    address: NetworkAddress

    # individual interface-bound sockets for:
    #  - receiving multicast traffic
    #  - sending multicast from a socket bound to WSD port
    #  - sending unicast messages from a random port
    recv_socket: socket.socket
    mc_send_socket: socket.socket
    uc_send_socket: socket.socket

    # addresses used for communication and data
    multicast_address: UdpAddress
    listen_address: Tuple
    aio_loop: asyncio.AbstractEventLoop

    # dictionary that holds INetworkPacketHandlers instances for sockets created above
    message_handlers: Dict[socket.socket, List[INetworkPacketHandler]]

    def __init__(self, address: NetworkAddress, aio_loop: asyncio.AbstractEventLoop) -> None:
        self.address = address

        self.recv_socket = socket.socket(self.address.family, socket.SOCK_DGRAM)
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.mc_send_socket = socket.socket(self.address.family, socket.SOCK_DGRAM)
        self.uc_send_socket = socket.socket(self.address.family, socket.SOCK_DGRAM)
        self.uc_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.message_handlers = {}
        self.aio_loop = aio_loop

        if self.address.family == socket.AF_INET:
            self.init_v4()
        elif self.address.family == socket.AF_INET6:
            self.init_v6()

        logger.info('joined multicast group {0} on {1}'.format(self.multicast_address.transport_str, self.address))
        logger.debug('transport address on {0} is {1}'.format(self.address.interface.name, self.address.transport_str))
        logger.debug('will listen for HTTP traffic on address {0}'.format(self.listen_address))

        # register calbacks for incoming data (also for mc)
        self.aio_loop.add_reader(self.recv_socket.fileno(), self.read_socket, self.recv_socket)
        self.aio_loop.add_reader(self.mc_send_socket.fileno(), self.read_socket, self.mc_send_socket)
        self.aio_loop.add_reader(self.uc_send_socket.fileno(), self.read_socket, self.uc_send_socket)

    def cleanup(self) -> None:
        self.aio_loop.remove_reader(self.recv_socket)
        self.aio_loop.remove_reader(self.mc_send_socket)
        self.aio_loop.remove_reader(self.uc_send_socket)

        self.recv_socket.close()
        self.mc_send_socket.close()
        self.uc_send_socket.close()

    def handles_address(self, address: NetworkAddress) -> bool:
        return self.address == address

    def init_v6(self) -> None:
        idx = self.address.interface.index
        raw_mc_addr = (WSD_MCAST_GRP_V6, WSD_UDP_PORT, 0x575C, idx)
        self.multicast_address = UdpAddress(self.address.family, raw_mc_addr, self.address.interface)

        # v6: member_request = { multicast_addr, intf_idx }
        mreq = (socket.inet_pton(self.address.family, WSD_MCAST_GRP_V6) + struct.pack('@I', idx))
        self.recv_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        self.recv_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        # Could anyone ask the Linux folks for the rationale for this!?
        if platform.system() == 'Linux':
            try:
                # supported starting from Linux 4.20
                IPV6_MULTICAST_ALL = 29
                self.recv_socket.setsockopt(socket.IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)
            except OSError as e:
                logger.warning('cannot unset all_multicast: {}'.format(e))

        # bind to network interface, i.e. scope and handle OS differences,
        # see Stevens: Unix Network Programming, Section 21.6, last paragraph
        try:
            self.recv_socket.bind((WSD_MCAST_GRP_V6, WSD_UDP_PORT, 0, idx))
        except OSError:
            self.recv_socket.bind(('::', 0, 0, idx))

        # bind unicast socket to interface address and WSD's udp port
        self.uc_send_socket.bind((str(self.address), WSD_UDP_PORT, 0, idx))

        self.mc_send_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        self.mc_send_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, args.hoplimit)
        self.mc_send_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)

        # bind multicast socket to interface address and a user-provided port (or random if unspecified)
        # this allows not-so-smart firewalls to whitelist another port to allow incoming replies
        try:
            self.mc_send_socket.bind((str(self.address), args.source_port, 0, idx))
        except OSError:
            logger.error('specified port {} already in use for {}'.format(args.source_port, str(self.address)))

        self.listen_address = (self.address.address_str, WSD_HTTP_PORT, 0, idx)

    def init_v4(self) -> None:
        idx = self.address.interface.index
        raw_mc_addr = (WSD_MCAST_GRP_V4, WSD_UDP_PORT)
        self.multicast_address = UdpAddress(self.address.family, raw_mc_addr, self.address.interface)

        # v4: member_request (ip_mreqn) = { multicast_addr, intf_addr, idx }
        if platform.system() == 'SunOS':
            mreq = (socket.inet_pton(self.address.family, WSD_MCAST_GRP_V4) + self.address.raw)
        else:
            mreq = (socket.inet_pton(self.address.family, WSD_MCAST_GRP_V4) + self.address.raw + struct.pack('@I', idx))
        self.recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        if platform.system() == 'Linux':
            IP_MULTICAST_ALL = 49
            self.recv_socket.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 0)

        try:
            self.recv_socket.bind((WSD_MCAST_GRP_V4, WSD_UDP_PORT))
        except OSError:
            self.recv_socket.bind(('', WSD_UDP_PORT))

        # bind unicast socket to interface address and WSD's udp port
        self.uc_send_socket.bind((self.address.address_str, WSD_UDP_PORT))

        if platform.system() == 'SunOS':
            self.mc_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, self.address.raw)
        else:
            self.mc_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
        # OpenBSD requires the optlen to be sizeof(char) for LOOP and TTL options
        # (see also https://github.com/python/cpython/issues/67316)
        self.mc_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, struct.pack('B', 0))
        self.mc_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('B', args.hoplimit))

        # bind multicast socket to interface address and a user-provided port (or random if unspecified)
        # this allows not-so-smart firewalls to whitelist another port to allow incoming replies
        try:
            self.mc_send_socket.bind((self.address.address_str, args.source_port))
        except OSError:
            logger.error('specified port {} already in use for {}'.format(args.source_port, self.address.address_str))

        self.listen_address = (self.address.address_str, WSD_HTTP_PORT)

    def add_handler(self, socket: socket.socket, handler: INetworkPacketHandler) -> None:
        # try:
        #    self.selector.register(socket, selectors.EVENT_READ, self)
        # except KeyError:
        #    # accept attempts of multiple registrations
        #    pass

        if socket in self.message_handlers:
            self.message_handlers[socket].append(handler)
        else:
            self.message_handlers[socket] = [handler]

    def remove_handler(self, socket: socket.socket, handler) -> None:
        if socket in self.message_handlers:
            if handler in self.message_handlers[socket]:
                self.message_handlers[socket].remove(handler)

    def read_socket(self, key: socket.socket) -> None:
        # TODO: refactor this
        s = None
        if key == self.uc_send_socket:
            s = self.uc_send_socket
        elif key == self.mc_send_socket:
            s = self.mc_send_socket
        elif key == self.recv_socket:
            s = self.recv_socket
        else:
            raise ValueError("Unknown socket passed as key.")

        msg, raw_address = s.recvfrom(WSD_MAX_LEN)
        address = UdpAddress(self.address.family, raw_address, self.address.interface)
        if s in self.message_handlers:
            for handler in self.message_handlers[s]:
                handler.handle_packet(msg.decode('utf-8'), address)

    def send(self, msg: bytes, addr: UdpAddress):
        # Request from a client must be answered from a socket that is bound
        # to the WSD port, i.e. the recv_socket. Messages to multicast
        # addresses are sent over the dedicated send socket.
        if addr == self.multicast_address:
            self.mc_send_socket.sendto(msg, addr.transport_address)
        else:
            self.uc_send_socket.sendto(msg, addr.transport_address)


# constants for WSD XML/SOAP parsing
WSA_URI: str = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'
WSD_URI: str = 'http://schemas.xmlsoap.org/ws/2005/04/discovery'
WSDP_URI: str = 'http://schemas.xmlsoap.org/ws/2006/02/devprof'

namespaces: Dict[str, str] = {
    'soap': 'http://www.w3.org/2003/05/soap-envelope',
    'wsa': WSA_URI,
    'wsd': WSD_URI,
    'wsx': 'http://schemas.xmlsoap.org/ws/2004/09/mex',
    'wsdp': WSDP_URI,
    'pnpx': 'http://schemas.microsoft.com/windows/pnpx/2005/10',
    'pub': 'http://schemas.microsoft.com/windows/pub/2005/07'
}

WSD_MAX_KNOWN_MESSAGES: int = 10

WSD_PROBE: str = WSD_URI + '/Probe'
WSD_PROBE_MATCH: str = WSD_URI + '/ProbeMatches'
WSD_RESOLVE: str = WSD_URI + '/Resolve'
WSD_RESOLVE_MATCH: str = WSD_URI + '/ResolveMatches'
WSD_HELLO: str = WSD_URI + '/Hello'
WSD_BYE: str = WSD_URI + '/Bye'
WSD_GET: str = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get'
WSD_GET_RESPONSE: str = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse'

WSD_TYPE_DEVICE: str = 'wsdp:Device'
PUB_COMPUTER: str = 'pub:Computer'
WSD_TYPE_DEVICE_COMPUTER: str = '{0} {1}'.format(WSD_TYPE_DEVICE, PUB_COMPUTER)

WSD_MCAST_GRP_V4: str = '239.255.255.250'
WSD_MCAST_GRP_V6: str = 'ff02::c'  # link-local

WSA_ANON: str = WSA_URI + '/role/anonymous'
WSA_DISCOVERY: str = 'urn:schemas-xmlsoap-org:ws:2005:04:discovery'

MIME_TYPE_SOAP_XML: str = 'application/soap+xml'

# protocol assignments (WSD spec/Section 2.4)
WSD_UDP_PORT: int = 3702
WSD_HTTP_PORT: int = 5357
WSD_MAX_LEN: int = 32767

WSDD_LISTEN_PORT = 5359

# SOAP/UDP transmission constants
MULTICAST_UDP_REPEAT: int = 4
UNICAST_UDP_REPEAT: int = 2
UDP_MIN_DELAY: int = 50
UDP_MAX_DELAY: int = 250
UDP_UPPER_DELAY: int = 500

# servers must recond in 4 seconds after probe arrives
PROBE_TIMEOUT: int = 4
MAX_STARTUP_PROBE_DELAY: int = 3

# some globals
wsd_instance_id: int = int(time.time())

WSDMessage = Tuple[ElementTree.Element, str]
MessageTypeHandler = Callable[[ElementTree.Element, ElementTree.Element], Optional[WSDMessage]]


class WSDMessageHandler(INetworkPacketHandler):
    known_messages: Deque[str] = collections.deque([], WSD_MAX_KNOWN_MESSAGES)

    handlers: Dict[str, MessageTypeHandler]
    pending_tasks: List[asyncio.Task]

    def __init__(self) -> None:
        self.handlers = {}
        self.pending_tasks = []

    def cleanup(self):
        pass

    # shortcuts for building WSD responses
    def add_endpoint_reference(self, parent: ElementTree.Element, endpoint: Optional[str] = None) -> None:
        epr = ElementTree.SubElement(parent, 'wsa:EndpointReference')
        address = ElementTree.SubElement(epr, 'wsa:Address')
        if endpoint is None:
            address.text = args.uuid.urn
        else:
            address.text = endpoint

    def add_metadata_version(self, parent: ElementTree.Element) -> None:
        meta_data = ElementTree.SubElement(parent, 'wsd:MetadataVersion')
        meta_data.text = '1'

    def add_types(self, parent: ElementTree.Element) -> None:
        dev_type = ElementTree.SubElement(parent, 'wsd:Types')
        dev_type.text = WSD_TYPE_DEVICE_COMPUTER

    def add_xaddr(self, parent: ElementTree.Element, transport_addr: str) -> None:
        if transport_addr:
            item = ElementTree.SubElement(parent, 'wsd:XAddrs')
            item.text = 'http://{0}:{1}/{2}'.format(transport_addr, WSD_HTTP_PORT, args.uuid)

    def build_message(self, to_addr: str, action_str: str, request_header: Optional[ElementTree.Element],
                      response: ElementTree.Element) -> str:
        retval = self.xml_to_str(self.build_message_tree(to_addr, action_str, request_header, response)[0])

        logger.debug('constructed xml for WSD message: {0}'.format(retval))

        return retval

    def build_message_tree(self, to_addr: str, action_str: str, request_header: Optional[ElementTree.Element],
                           body: Optional[ElementTree.Element]) -> Tuple[ElementTree.Element, str]:
        """
        Build a WSD message with a given action string including SOAP header.

        The message can be constructed based on a response to another
        message (given by its header) and with a optional response that
        serves as the message's body
        """
        root = ElementTree.Element('soap:Envelope')
        header = ElementTree.SubElement(root, 'soap:Header')

        to = ElementTree.SubElement(header, 'wsa:To')
        to.text = to_addr

        action = ElementTree.SubElement(header, 'wsa:Action')
        action.text = action_str

        msg_id = ElementTree.SubElement(header, 'wsa:MessageID')
        msg_id.text = uuid.uuid1().urn

        if request_header is not None:
            req_msg_id = request_header.find('./wsa:MessageID', namespaces)
            if req_msg_id is not None:
                relates_to = ElementTree.SubElement(header, 'wsa:RelatesTo')
                relates_to.text = req_msg_id.text

        self.add_header_elements(header, action_str)

        body_root = ElementTree.SubElement(root, 'soap:Body')
        if body is not None:
            body_root.append(body)

        for prefix, uri in namespaces.items():
            root.attrib['xmlns:' + prefix] = uri

        return root, msg_id.text

    def add_header_elements(self, header: ElementTree.Element, extra: Any) -> None:
        pass

    def handle_message(self, msg: str, src: Optional[UdpAddress] = None) -> Optional[str]:
        """
        handle a WSD message
        """
        try:
            tree = ETfromString(msg)
        except ElementTree.ParseError:
            return None

        header = tree.find('./soap:Header', namespaces)
        if header is None:
            return None

        msg_id_tag = header.find('./wsa:MessageID', namespaces)
        if msg_id_tag is None:
            return None

        msg_id = str(msg_id_tag.text)

        # check for duplicates
        if self.is_duplicated_msg(msg_id):
            logger.debug('known message ({0}): dropping it'.format(msg_id))
            return None

        action_tag = header.find('./wsa:Action', namespaces)
        if action_tag is None:
            return None

        action: str = str(action_tag.text)
        _, _, action_method = action.rpartition('/')

        if src:
            logger.info('{}:{}({}) - - "{} {} UDP" - -'.format(
                src.transport_str, src.port, src.interface, action_method, msg_id))
        else:
            # http logging is already done by according server
            logger.debug('processing WSD {} message ({})'.format(action_method, msg_id))

        body = tree.find('./soap:Body', namespaces)
        if body is None:
            return None

        logger.debug('incoming message content is {0}'.format(msg))
        if action in self.handlers:
            handler = self.handlers[action]
            retval = handler(header, body)
            if retval is not None:
                response, response_type = retval
                return self.build_message(WSA_ANON, response_type, header, response)
        else:
            logger.debug('unhandled action {0}/{1}'.format(action, msg_id))

        return None

    def is_duplicated_msg(self, msg_id: str) -> bool:
        """
        Check for a duplicated message.

        Implements SOAP-over-UDP Appendix II Item 2
        """
        if msg_id in type(self).known_messages:
            return True

        type(self).known_messages.append(msg_id)

        return False

    def xml_to_str(self, xml: ElementTree.Element) -> str:
        retval = '<?xml version="1.0" encoding="utf-8"?>'
        retval = retval + ElementTree.tostring(xml, encoding='utf-8').decode('utf-8')

        return retval


class WSDUDPMessageHandler(WSDMessageHandler):
    """
    A message handler that handles traffic received via MutlicastHandler.
    """

    mch: MulticastHandler
    tearing_down: bool

    def __init__(self, mch: MulticastHandler) -> None:
        super().__init__()

        self.mch = mch
        self.tearing_down = False

    def teardown(self):
        self.tearing_down = True

    def send_datagram(self, msg: str, dst: UdpAddress) -> None:
        try:
            self.mch.send(msg.encode('utf-8'), dst)
        except Exception as e:
            logger.error('error while sending packet on {}: {}'.format(self.mch.address.interface, e))

    def enqueue_datagram(self, msg: str, address: UdpAddress, msg_type: Optional[str] = None) -> None:
        if msg_type:
            logger.info('scheduling {0} message via {1} to {2}'.format(msg_type, address.interface, address))

        schedule_task = self.mch.aio_loop.create_task(self.schedule_datagram(msg, address))
        # Add this task to the pending list during teardown to wait during shutdown
        if self.tearing_down:
            self.pending_tasks.append(schedule_task)

    async def schedule_datagram(self, msg: str, address: UdpAddress) -> None:
        """
        Schedule to send the given message to the given address.

        Implements SOAP over UDP, Appendix I.
        """

        self.send_datagram(msg, address)

        delta = 0
        msg_count = MULTICAST_UDP_REPEAT if address == self.mch.multicast_address else UNICAST_UDP_REPEAT
        delta = random.randint(UDP_MIN_DELAY, UDP_MAX_DELAY)
        for i in range(msg_count - 1):
            await asyncio.sleep(delta / 1000.0)
            self.send_datagram(msg, address)
            delta = min(delta * 2, UDP_UPPER_DELAY)


class WSDDiscoveredDevice:

    # a dict of discovered devices with their UUID as key
    instances: Dict[str, 'WSDDiscoveredDevice'] = {}

    addresses: Dict[str, Set[str]]
    props: Dict[str, str]
    display_name: str
    last_seen: float
    types: Set[str]

    def __init__(self, xml_str: str, xaddr: str, interface: NetworkInterface) -> None:
        self.last_seen = 0.0
        self.addresses = {}
        self.props = {}
        self.display_name = ''
        self.types = set()

        self.update(xml_str, xaddr, interface)

    def update(self, xml_str: str, xaddr: str, interface: NetworkInterface) -> None:
        try:
            tree = ETfromString(xml_str)
        except ElementTree.ParseError:
            return None
        mds_path = 'soap:Body/wsx:Metadata/wsx:MetadataSection'
        sections = tree.findall(mds_path, namespaces)
        for section in sections:
            dialect = section.attrib['Dialect']
            if dialect == WSDP_URI + '/ThisDevice':
                self.extract_wsdp_props(section, dialect)
            elif dialect == WSDP_URI + '/ThisModel':
                self.extract_wsdp_props(section, dialect)
            elif dialect == WSDP_URI + '/Relationship':
                host_xpath = 'wsdp:Relationship[@Type="{}/host"]/wsdp:Host'.format(WSDP_URI)
                host_sec = section.find(host_xpath, namespaces)
                if (host_sec is not None):
                    self.extract_host_props(host_sec)
            else:
                logger.debug('unknown metadata dialect ({})'.format(dialect))

        url = urllib.parse.urlparse(xaddr)
        addr, _, _ = url.netloc.rpartition(':')
        report = True
        if interface.name not in self.addresses:
            self.addresses[interface.name] = set([addr])
        else:
            if addr not in self.addresses[interface.name]:
                self.addresses[interface.name].add(addr)
            else:
                report = False

        self.last_seen = time.time()
        if ('DisplayName' in self.props) and ('BelongsTo' in self.props) and (report):
            self.display_name = self.props['DisplayName']
            logger.info('discovered {} in {} on {}'.format(self.display_name, self.props['BelongsTo'], addr))
        elif ('FriendlyName' in self.props) and (report):
            self.display_name = self.props['FriendlyName']
            logger.info('discovered {} on {}'.format(self.display_name, addr))

        logger.debug(str(self.props))

    def extract_wsdp_props(self, root: ElementTree.Element, dialect: str) -> None:
        _, _, propsRoot = dialect.rpartition('/')
        # XPath support is limited, so filter by namespace on our own
        nodes = root.findall('./wsdp:{0}/*'.format(propsRoot), namespaces)
        ns_prefix = '{{{}}}'.format(WSDP_URI)
        prop_nodes = [n for n in nodes if n.tag.startswith(ns_prefix)]
        for node in prop_nodes:
            tag_name = node.tag[len(ns_prefix):]
            self.props[tag_name] = str(node.text)

    def extract_host_props(self, root: ElementTree.Element) -> None:
        self.types = set(root.findtext('wsdp:Types', '', namespaces).split(' '))
        if PUB_COMPUTER not in self.types:
            return

        comp = root.findtext(PUB_COMPUTER, '', namespaces)
        self.props['DisplayName'], _, self.props['BelongsTo'] = (
            comp.partition('/'))


class WSDClient(WSDUDPMessageHandler):

    instances: ClassVar[List['WSDClient']] = []
    probes: Dict[str, float]

    def __init__(self, mch: MulticastHandler) -> None:
        super().__init__(mch)

        WSDClient.instances.append(self)

        self.mch.add_handler(self.mch.mc_send_socket, self)
        self.mch.add_handler(self.mch.recv_socket, self)

        self.probes = {}

        self.handlers[WSD_HELLO] = self.handle_hello
        self.handlers[WSD_BYE] = self.handle_bye
        self.handlers[WSD_PROBE_MATCH] = self.handle_probe_match
        self.handlers[WSD_RESOLVE_MATCH] = self.handle_resolve_match

        # avoid packet storm when hosts come up by delaying initial probe
        time.sleep(random.randint(0, MAX_STARTUP_PROBE_DELAY))
        self.send_probe()

    def cleanup(self) -> None:
        super().cleanup()
        WSDClient.instances.remove(self)

        self.mch.remove_handler(self.mch.mc_send_socket, self)
        self.mch.remove_handler(self.mch.recv_socket, self)

    def send_probe(self) -> None:
        """WS-Discovery, Section 4.3, Probe message"""
        self.remove_outdated_probes()

        probe = ElementTree.Element('wsd:Probe')
        ElementTree.SubElement(probe, 'wsd:Types').text = WSD_TYPE_DEVICE

        xml, i = self.build_message_tree(WSA_DISCOVERY, WSD_PROBE, None, probe)
        self.enqueue_datagram(self.xml_to_str(xml), self.mch.multicast_address, msg_type='Probe')
        self.probes[i] = time.time()

    def teardown(self) -> None:
        super().teardown()
        self.remove_outdated_probes()

    def handle_packet(self, msg: str, src: Optional[UdpAddress] = None) -> None:
        self.handle_message(msg, src)

    def __extract_xaddr(self, xaddrs: str) -> Optional[str]:
        for addr in xaddrs.strip().split():
            if (self.mch.address.family == socket.AF_INET6) and ('//[fe80::' in addr):
                # use first link-local address for IPv6
                return addr
            elif self.mch.address.family == socket.AF_INET:
                # use first (and very likely the only) IPv4 address
                return addr

        return None

    def handle_hello(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
        pm_path = 'wsd:Hello'
        endpoint, xaddrs = self.extract_endpoint_metadata(body, pm_path)
        if not xaddrs:
            logger.info('Hello without XAddrs, sending resolve')
            msg = self.build_resolve_message(str(endpoint))
            self.enqueue_datagram(msg, self.mch.multicast_address)
            return None

        xaddr = self.__extract_xaddr(xaddrs)
        if xaddr is None:
            return None

        logger.info('Hello from {} on {}'.format(endpoint, xaddr))
        self.perform_metadata_exchange(endpoint, xaddr)
        return None

    def handle_bye(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
        bye_path = 'wsd:Bye'
        endpoint, _ = self.extract_endpoint_metadata(body, bye_path)
        device_uri = str(urllib.parse.urlparse(endpoint).geturl())
        if device_uri in WSDDiscoveredDevice.instances:
            del WSDDiscoveredDevice.instances[device_uri]

        return None

    def handle_probe_match(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
        # do not handle to probematches issued not sent by ourself
        rel_msg = header.findtext('wsa:RelatesTo', None, namespaces)
        if rel_msg not in self.probes:
            logger.debug("unknown probe {}".format(rel_msg))
            return None

        # if XAddrs are missing, issue resolve request
        pm_path = 'wsd:ProbeMatches/wsd:ProbeMatch'
        endpoint, xaddrs = self.extract_endpoint_metadata(body, pm_path)
        if not xaddrs:
            logger.debug('probe match without XAddrs, sending resolve')
            msg = self.build_resolve_message(str(endpoint))
            self.enqueue_datagram(msg, self.mch.multicast_address)
            return None

        xaddr = self.__extract_xaddr(xaddrs)
        if xaddr is None:
            return None

        logger.debug('probe match for {} on {}'.format(endpoint, xaddr))
        self.perform_metadata_exchange(endpoint, xaddr)

        return None

    def build_resolve_message(self, endpoint: str) -> str:
        resolve = ElementTree.Element('wsd:Resolve')
        self.add_endpoint_reference(resolve, endpoint)

        return self.build_message(WSA_DISCOVERY, WSD_RESOLVE, None, resolve)

    def handle_resolve_match(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
        rm_path = 'wsd:ResolveMatches/wsd:ResolveMatch'
        endpoint, xaddrs = self.extract_endpoint_metadata(body, rm_path)
        if not endpoint or not xaddrs:
            logger.debug('resolve match without endpoint/xaddr')
            return None

        xaddr = self.__extract_xaddr(xaddrs)
        if xaddr is None:
            return None

        logger.debug('resolve match for {} on {}'.format(endpoint, xaddr))
        self.perform_metadata_exchange(endpoint, xaddr)

        return None

    def extract_endpoint_metadata(self, body: ElementTree.Element, prefix: str) -> Tuple[Optional[str], Optional[str]]:
        prefix = prefix + '/'
        addr_path = 'wsa:EndpointReference/wsa:Address'

        endpoint = body.findtext(prefix + addr_path, namespaces=namespaces)
        xaddrs = body.findtext(prefix + 'wsd:XAddrs', namespaces=namespaces)

        return endpoint, xaddrs

    def perform_metadata_exchange(self, endpoint, xaddr: str):
        if not (xaddr.startswith('http://') or xaddr.startswith('https://')):
            logger.debug('invalid XAddr: {}'.format(xaddr))
            return

        host = None
        url = xaddr
        if self.mch.address.family == socket.AF_INET6:
            host = '[{}]'.format(url.partition('[')[2].partition(']')[0])
            url = url.replace(']', '%{}]'.format(self.mch.address.interface))

        body = self.build_getmetadata_message(endpoint)
        request = urllib.request.Request(url, data=body.encode('utf-8'), method='POST')
        request.add_header('Content-Type', 'application/soap+xml')
        request.add_header('User-Agent', 'wsdd')
        if host is not None:
            request.add_header('Host', host)

        try:
            with urllib.request.urlopen(request, None, args.metadata_timeout) as stream:
                self.handle_metadata(stream.read(), endpoint, xaddr)
        except urllib.error.URLError as e:
            logger.warning('could not fetch metadata from: {} {}'.format(url, e))
        except TimeoutError:
            logger.warning('metadata exchange with {} timed out'.format(url))

    def build_getmetadata_message(self, endpoint) -> str:
        tree, _ = self.build_message_tree(endpoint, WSD_GET, None, None)
        return self.xml_to_str(tree)

    def handle_metadata(self, meta: str, endpoint: str, xaddr: str) -> None:
        device_uri = urllib.parse.urlparse(endpoint).geturl()
        if device_uri in WSDDiscoveredDevice.instances:
            WSDDiscoveredDevice.instances[device_uri].update(meta, xaddr, self.mch.address.interface)
        else:
            WSDDiscoveredDevice.instances[device_uri] = WSDDiscoveredDevice(meta, xaddr, self.mch.address.interface)

    def remove_outdated_probes(self) -> None:
        cut = time.time() - PROBE_TIMEOUT * 2
        self.probes = dict(filter(lambda x: x[1] > cut, self.probes.items()))

    def add_header_elements(self, header: ElementTree.Element, extra: Any) -> None:
        action_str = extra
        if action_str == WSD_GET:
            reply_to = ElementTree.SubElement(header, 'wsa:ReplyTo')
            addr = ElementTree.SubElement(reply_to, 'wsa:Address')
            addr.text = WSA_ANON

            wsa_from = ElementTree.SubElement(header, 'wsa:From')
            addr = ElementTree.SubElement(wsa_from, 'wsa:Address')
            addr.text = args.uuid.urn


class WSDHost(WSDUDPMessageHandler):
    """Class for handling WSD requests coming from UDP datagrams."""

    message_number: ClassVar[int] = 0
    instances: ClassVar[List['WSDHost']] = []

    def __init__(self, mch: MulticastHandler) -> None:
        super().__init__(mch)

        WSDHost.instances.append(self)

        self.mch.add_handler(self.mch.recv_socket, self)

        self.handlers[WSD_PROBE] = self.handle_probe
        self.handlers[WSD_RESOLVE] = self.handle_resolve

        self.send_hello()

    def cleanup(self) -> None:
        super().cleanup()
        WSDHost.instances.remove(self)

    def teardown(self) -> None:
        super().teardown()
        self.send_bye()

    def handle_packet(self, msg: str, src: UdpAddress) -> None:
        reply = self.handle_message(msg, src)
        if reply:
            self.enqueue_datagram(reply, src)

    def send_hello(self) -> None:
        """WS-Discovery, Section 4.1, Hello message"""
        hello = ElementTree.Element('wsd:Hello')
        self.add_endpoint_reference(hello)
        # THINK: Microsoft does not send the transport address here due to privacy reasons. Could make this optional.
        self.add_xaddr(hello, self.mch.address.transport_str)
        self.add_metadata_version(hello)

        msg = self.build_message(WSA_DISCOVERY, WSD_HELLO, None, hello)
        self.enqueue_datagram(msg, self.mch.multicast_address, msg_type='Hello')

    def send_bye(self) -> None:
        """WS-Discovery, Section 4.2, Bye message"""
        bye = ElementTree.Element('wsd:Bye')
        self.add_endpoint_reference(bye)

        msg = self.build_message(WSA_DISCOVERY, WSD_BYE, None, bye)
        self.enqueue_datagram(msg, self.mch.multicast_address, msg_type='Bye')

    def handle_probe(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
        probe = body.find('./wsd:Probe', namespaces)
        if probe is None:
            return None

        scopes = probe.find('./wsd:Scopes', namespaces)

        if scopes:
            # THINK: send fault message (see p. 21 in WSD)
            logger.debug('scopes ({}) unsupported but probed'.format(scopes))
            return None

        types_elem = probe.find('./wsd:Types', namespaces)
        if types_elem is None:
            logger.debug('Probe message lacks wsd:Types element. Ignored.')
            return None

        types = types_elem.text
        if not types == WSD_TYPE_DEVICE:
            logger.debug('unknown discovery type ({}) for probe'.format(types))
            return None

        matches = ElementTree.Element('wsd:ProbeMatches')
        match = ElementTree.SubElement(matches, 'wsd:ProbeMatch')
        self.add_endpoint_reference(match)
        self.add_types(match)
        self.add_metadata_version(match)

        return matches, WSD_PROBE_MATCH

    def handle_resolve(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
        resolve = body.find('./wsd:Resolve', namespaces)
        if resolve is None:
            return None

        addr = resolve.find('./wsa:EndpointReference/wsa:Address', namespaces)
        if addr is None:
            logger.debug('invalid resolve request: missing endpoint address')
            return None

        if not addr.text == args.uuid.urn:
            logger.debug('invalid resolve request: address ({}) does not match own one ({})'.format(
                addr.text, args.uuid.urn))
            return None

        matches = ElementTree.Element('wsd:ResolveMatches')
        match = ElementTree.SubElement(matches, 'wsd:ResolveMatch')
        self.add_endpoint_reference(match)
        self.add_types(match)
        self.add_xaddr(match, self.mch.address.transport_str)
        self.add_metadata_version(match)

        return matches, WSD_RESOLVE_MATCH

    def add_header_elements(self, header: ElementTree.Element, extra: Any):
        ElementTree.SubElement(header, 'wsd:AppSequence', {
            'InstanceId': str(wsd_instance_id),
            'SequenceId': uuid.uuid1().urn,
            'MessageNumber': str(type(self).message_number)})

        type(self).message_number += 1


class WSDHttpMessageHandler(WSDMessageHandler):

    def __init__(self) -> None:
        super().__init__()

        self.handlers[WSD_GET] = self.handle_get

    def handle_get(self, header: ElementTree.Element, body: ElementTree.Element) -> WSDMessage:
        # see https://msdn.microsoft.com/en-us/library/hh441784.aspx for an
        # example. Some of the properties below might be made configurable
        # in future releases.
        metadata = ElementTree.Element('wsx:Metadata')
        section = ElementTree.SubElement(metadata, 'wsx:MetadataSection', {'Dialect': WSDP_URI + '/ThisDevice'})
        device = ElementTree.SubElement(section, 'wsdp:ThisDevice')
        ElementTree.SubElement(device, 'wsdp:FriendlyName').text = ('WSD Device {0}'.format(args.hostname))
        ElementTree.SubElement(device, 'wsdp:FirmwareVersion').text = '1.0'
        ElementTree.SubElement(device, 'wsdp:SerialNumber').text = '1'

        section = ElementTree.SubElement(metadata, 'wsx:MetadataSection', {'Dialect': WSDP_URI + '/ThisModel'})
        model = ElementTree.SubElement(section, 'wsdp:ThisModel')
        ElementTree.SubElement(model, 'wsdp:Manufacturer').text = 'wsdd'
        ElementTree.SubElement(model, 'wsdp:ModelName').text = 'wsdd'
        ElementTree.SubElement(model, 'pnpx:DeviceCategory').text = 'Computers'

        section = ElementTree.SubElement(metadata, 'wsx:MetadataSection', {'Dialect': WSDP_URI + '/Relationship'})
        rel = ElementTree.SubElement(section, 'wsdp:Relationship', {'Type': WSDP_URI + '/host'})
        host = ElementTree.SubElement(rel, 'wsdp:Host')
        self.add_endpoint_reference(host)
        ElementTree.SubElement(host, 'wsdp:Types').text = PUB_COMPUTER
        ElementTree.SubElement(host, 'wsdp:ServiceId').text = args.uuid.urn

        fmt = '{0}/Domain:{1}' if args.domain else '{0}/Workgroup:{1}'
        value = args.domain if args.domain else args.workgroup.upper()
        if args.domain:
            dh = args.hostname if args.preserve_case else args.hostname.lower()
        else:
            dh = args.hostname if args.preserve_case else args.hostname.upper()

        ElementTree.SubElement(host, PUB_COMPUTER).text = fmt.format(dh, value)

        return metadata, WSD_GET_RESPONSE


class WSDHttpServer(http.server.HTTPServer):
    """ HTTP server both with IPv6 support and WSD handling """

    mch: MulticastHandler
    aio_loop: asyncio.AbstractEventLoop
    wsd_handler: WSDHttpMessageHandler
    registered: bool

    def __init__(self, mch: MulticastHandler, aio_loop: asyncio.AbstractEventLoop):
        # hacky way to convince HTTP/SocketServer of the address family
        type(self).address_family = mch.address.family

        self.mch = mch
        self.aio_loop = aio_loop
        self.wsd_handler = WSDHttpMessageHandler()
        self.registered = False

        # WSDHttpRequestHandler is a BaseHTTPRequestHandler. Passing to the parent constructor is therefore safe and
        # we can ignore the type error reported by mypy
        super().__init__(mch.listen_address, WSDHttpRequestHandler)  # type: ignore

    def server_bind(self) -> None:
        if self.mch.address.family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        super().server_bind()

    def server_activate(self) -> None:
        super().server_activate()
        self.aio_loop.add_reader(self.fileno(), self.handle_request)
        self.registered = True

    def server_close(self) -> None:
        if self.registered:
            self.aio_loop.remove_reader(self.fileno())
        super().server_close()


class WSDHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    """Class for handling WSD requests coming over HTTP"""

    def log_message(self, fmt, *args) -> None:
        logger.info("{} - - ".format(self.address_string()) + fmt % args)

    def do_POST(self) -> None:
        if self.path != '/' + str(args.uuid):
            self.send_error(http.HTTPStatus.NOT_FOUND)

        ct = self.headers['Content-Type']
        if ct is None or not ct.startswith(MIME_TYPE_SOAP_XML):
            self.send_error(http.HTTPStatus.BAD_REQUEST, 'Invalid Content-Type')

        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        response = self.server.wsd_handler.handle_message(body)  # type: ignore
        if response:
            self.send_response(http.HTTPStatus.OK)
            self.send_header('Content-Type', MIME_TYPE_SOAP_XML)
            self.end_headers()
            self.wfile.write(response.encode('utf-8'))
        else:
            self.send_error(http.HTTPStatus.BAD_REQUEST)


class ApiServer:

    address_monitor: 'NetworkAddressMonitor'
    clients: List[asyncio.StreamWriter]

    def __init__(self, aio_loop: asyncio.AbstractEventLoop, listen_address: Any,
                 address_monitor: 'NetworkAddressMonitor') -> None:
        self.server = None
        self.clients = []
        self.address_monitor = address_monitor

        # defer server creation
        self.create_task = aio_loop.create_task(self.create_server(aio_loop, listen_address))

    async def create_server(self, aio_loop: asyncio.AbstractEventLoop, listen_address: Any) -> None:

        # It appears mypy is not able to check the argument to create_task and the return value of start_server
        # correctly. The docs say start_server returns a coroutine and the create_task takes a coro. And: It works.
        # Thus, we ignore type errors here.
        if isinstance(listen_address, socket.SocketType):
            # create socket from systemd file descriptor/socket
            self.server = await aio_loop.create_task(asyncio.start_unix_server(  # type: ignore
                self.on_connect, sock=listen_address))
        elif isinstance(listen_address, int) or listen_address.isnumeric():
            self.server = await aio_loop.create_task(asyncio.start_server(  # type: ignore
                self.on_connect, host='localhost', port=int(listen_address), reuse_address=True,
                reuse_port=True))
        else:
            self.server = await aio_loop.create_task(asyncio.start_unix_server(  # type: ignore
                self.on_connect, path=listen_address))

    async def on_connect(self, read_stream: asyncio.StreamReader, write_stream: asyncio.StreamWriter) -> None:
        self.clients.append(write_stream)
        while True:
            try:
                line = await read_stream.readline()
                if line:
                    self.handle_command(str(line.strip(), 'utf-8'), write_stream)
                    if not write_stream.is_closing():
                        await write_stream.drain()
                else:
                    self.clients.remove(write_stream)
                    write_stream.close()
                    return
            except UnicodeDecodeError as e:
                logger.debug('invalid input utf8', e)
            except Exception as e:
                logger.warning('exception in API client', e)
                self.clients.remove(write_stream)
                write_stream.close()
                return

    def handle_command(self, line: str, write_stream: asyncio.StreamWriter) -> None:
        words = line.split()
        if len(words) == 0:
            return

        command = words[0]
        command_args = words[1:]
        if command == 'probe' and args.discovery:
            intf = command_args[0] if command_args else None
            logger.debug('probing devices on {} upon request'.format(intf))
            for client in self.get_clients_by_interface(intf):
                client.send_probe()
        elif command == 'clear' and args.discovery:
            logger.debug('clearing list of known devices')
            WSDDiscoveredDevice.instances.clear()
        elif command == 'list' and args.discovery:
            wsd_type = command_args[0] if command_args else None
            write_stream.write(bytes(self.get_list_reply(wsd_type), 'utf-8'))
        elif command == 'quit':
            write_stream.close()
        elif command == 'start':
            self.address_monitor.enumerate()
        elif command == 'stop':
            self.address_monitor.teardown()
        else:
            logger.debug('could not handle API request: {}'.format(line))

    def get_clients_by_interface(self, interface: Optional[str]) -> List[WSDClient]:
        return [c for c in WSDClient.instances if c.mch.address.interface.name == interface or not interface]

    def get_list_reply(self, wsd_type: Optional[str]) -> str:
        retval = ''
        for dev_uri, dev in WSDDiscoveredDevice.instances.items():
            if wsd_type and (wsd_type not in dev.types):
                continue

            addrs_str = []
            for addrs in dev.addresses.items():
                addrs_str.append(', '.join(['{}'.format(a) for a in addrs]))

            retval = retval + '{}\t{}\t{}\t{}\t{}\t{}\n'.format(
                dev_uri,
                dev.display_name,
                dev.props['BelongsTo'] if 'BelongsTo' in dev.props else '',
                datetime.datetime.fromtimestamp(dev.last_seen).isoformat('T', 'seconds'),
                ','.join(addrs_str),
                ','.join(dev.types))

        retval += '.\n'
        return retval

    async def cleanup(self) -> None:
        # ensure the server is not created after we have teared down
        await self.create_task
        if self.server:
            self.server.close()
            for client in self.clients:
                client.close()
            await self.server.wait_closed()


class MetaEnumAfterInit(type):

    def __call__(cls, *cargs, **kwargs):
        obj = super().__call__(*cargs, **kwargs)
        if not args.no_autostart:
            obj.enumerate()
        return obj


class NetworkAddressMonitor(metaclass=MetaEnumAfterInit):
    """
    Observes changes of network addresses, handles addition and removal of
    network addresses, and filters for addresses/interfaces that are or are not
    handled. The actual OS-specific implementation that detects the changes is
    done in subclasses. This class is used as a singleton
    """

    instance: ClassVar[object] = None

    interfaces: Dict[int, NetworkInterface]
    aio_loop: asyncio.AbstractEventLoop
    mchs: List[MulticastHandler]
    http_servers: List[WSDHttpServer]
    teardown_tasks: List[asyncio.Task]
    active: bool

    def __init__(self, aio_loop: asyncio.AbstractEventLoop) -> None:

        if NetworkAddressMonitor.instance is not None:
            raise RuntimeError('Instance of NetworkAddressMonitor already created')

        NetworkAddressMonitor.instance = self

        self.interfaces = {}
        self.aio_loop = aio_loop

        self.mchs = []
        self.http_servers = []
        self.teardown_tasks = []

        self.active = False

    def enumerate(self) -> None:
        """
        Performs an initial enumeration of addresses and sets up everything
        for observing future changes.
        """
        if self.active:
            return

        self.active = True
        self.do_enumerate()

    def do_enumerate(self) -> None:
        pass

    def handle_change(self) -> None:
        """ handle network change message """
        pass

    def add_interface(self, interface: NetworkInterface) -> NetworkInterface:
        # TODO: Cleanup
        if interface.index in self.interfaces:
            pass
            # self.interfaces[idx].name = name
        else:
            self.interfaces[interface.index] = interface

        return self.interfaces[interface.index]

    def is_address_handled(self, address: NetworkAddress) -> bool:
        # do not handle anything when we are not active
        if not self.active:
            return False

        # filter out address families we are not interested in
        if args.ipv4only and address.family != socket.AF_INET:
            return False
        if args.ipv6only and address.family != socket.AF_INET6:
            return False

        if not address.is_multicastable:
            return False

        # Use interface only if it's in the list of user-provided interface names
        if ((args.interface) and (address.interface.name not in args.interface)
                and (address.address_str not in args.interface)):
            return False

        return True

    def handle_new_address(self, address: NetworkAddress) -> None:
        logger.debug('new address {}'.format(address))

        if not self.is_address_handled(address):
            logger.debug('ignoring that address on {}'.format(address.interface))
            return

        # filter out what is not wanted
        # Ignore addresses or interfaces we already handle. There can only be
        # one multicast handler per address family and network interface
        for mch in self.mchs:
            if mch.handles_address(address):
                return

        logger.debug('handling traffic for {}'.format(address))
        mch = MulticastHandler(address, self.aio_loop)
        self.mchs.append(mch)

        if not args.no_host:
            WSDHost(mch)
            if not args.no_http:
                self.http_servers.append(WSDHttpServer(mch, self.aio_loop))

        if args.discovery:
            WSDClient(mch)

    def handle_deleted_address(self, address: NetworkAddress) -> None:
        logger.info('deleted address {}'.format(address))

        if not self.is_address_handled(address):
            return

        mch: Optional[MulticastHandler] = self.get_mch_by_address(address)
        if mch is None:
            return

        # Do not tear the client/hosts down. Saying goodbye does not work
        # because the address is already gone (at least on Linux).
        for c in WSDClient.instances:
            if c.mch == mch:
                c.cleanup()
                break
        for h in WSDHost.instances:
            if h.mch == mch:
                h.cleanup()
                break
        for s in self.http_servers:
            if s.mch == mch:
                s.server_close()
                self.http_servers.remove(s)

        mch.cleanup()
        self.mchs.remove(mch)

    def teardown(self) -> None:
        if not self.active:
            return

        self.active = False

        # return if we are still in tear down process
        if len(self.teardown_tasks) > 0:
            return

        for h in WSDHost.instances:
            h.teardown()
            h.cleanup()
            self.teardown_tasks.extend(h.pending_tasks)

        for c in WSDClient.instances:
            c.teardown()
            c.cleanup()
            self.teardown_tasks.extend(c.pending_tasks)

        for s in self.http_servers:
            s.server_close()

        self.http_servers.clear()

        if not self.teardown_tasks:
            return

        if not self.aio_loop.is_running():
            # Wait here for all pending tasks so that the main loop can be finished on termination.
            self.aio_loop.run_until_complete(asyncio.gather(*self.teardown_tasks))
        else:
            for t in self.teardown_tasks:
                t.add_done_callback(self.mch_teardown)

    def mch_teardown(self, task) -> None:
        if any([not t.done() for t in self.teardown_tasks]):
            return

        self.teardown_tasks.clear()

        for mch in self.mchs:
            mch.cleanup()
        self.mchs.clear()

    def cleanup(self) -> None:
        self.teardown()

    def get_mch_by_address(self, address: NetworkAddress) -> Optional[MulticastHandler]:
        """
        Get the MCI for the address, its family and the interface.
        adress must be given as a string.
        """
        for retval in self.mchs:
            if retval.handles_address(address):
                return retval

        return None


# from rtnetlink.h
RTMGRP_LINK: int = 1
RTMGRP_IPV4_IFADDR: int = 0x10
RTMGRP_IPV6_IFADDR: int = 0x100

# from netlink.h (struct nlmsghdr)
NLM_HDR_DEF: str = '@IHHII'

NLM_F_REQUEST: int = 0x01
NLM_F_ROOT: int = 0x100
NLM_F_MATCH: int = 0x200
NLM_F_DUMP: int = NLM_F_ROOT | NLM_F_MATCH

# self defines
NLM_HDR_ALIGNTO: int = 4

# ifa flags
IFA_F_DADFAILED: int = 0x08
IFA_F_HOMEADDRESS: int = 0x10
IFA_F_DEPRECATED: int = 0x20
IFA_F_TENTATIVE: int = 0x40

# from if_addr.h (struct ifaddrmsg)
IFADDR_MSG_DEF: str = '@BBBBI'
IFA_ADDRESS: int = 1
IFA_LOCAL: int = 2
IFA_LABEL: int = 3
IFA_FLAGS: int = 8
IFA_MSG_LEN: int = 8

RTA_ALIGNTO: int = 4
RTA_LEN: int = 4


def align_to(x: int, n: int) -> int:
    return ((x + n - 1) // n) * n


class NetlinkAddressMonitor(NetworkAddressMonitor):
    """
    Implementation of the AddressMonitor for Netlink sockets, i.e. Linux
    """

    RTM_NEWADDR: int = 20
    RTM_DELADDR: int = 21
    RTM_GETADDR: int = 22

    socket: socket.socket

    def __init__(self, aio_loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(aio_loop)

        rtm_groups = RTMGRP_LINK
        if not args.ipv4only:
            rtm_groups = rtm_groups | RTMGRP_IPV6_IFADDR
        if not args.ipv6only:
            rtm_groups = rtm_groups | RTMGRP_IPV4_IFADDR

        self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
        self.socket.bind((0, rtm_groups))
        self.aio_loop.add_reader(self.socket.fileno(), self.handle_change)

        self.NLM_HDR_LEN = struct.calcsize(NLM_HDR_DEF)

    def do_enumerate(self) -> None:
        super().do_enumerate()

        kernel = (0, 0)
        # Append an unsigned byte to the header for the request.
        req = struct.pack(NLM_HDR_DEF + 'B', self.NLM_HDR_LEN + 1, self.RTM_GETADDR,
                          NLM_F_REQUEST | NLM_F_DUMP, 1, 0, socket.AF_PACKET)
        self.socket.sendto(req, kernel)

    def handle_change(self) -> None:
        super().handle_change()

        buf, src = self.socket.recvfrom(4096)
        logger.debug('netlink message with {} bytes'.format(len(buf)))

        offset = 0
        while offset < len(buf):
            h_len, h_type, _, _, _ = struct.unpack_from(NLM_HDR_DEF, buf, offset)
            offset += self.NLM_HDR_LEN

            msg_len = h_len - self.NLM_HDR_LEN
            if msg_len < 0:
                break

            if h_type != self.RTM_NEWADDR and h_type != self.RTM_DELADDR:
                logger.debug('invalid rtm_message type {}'.format(h_type))
                offset += align_to(msg_len, NLM_HDR_ALIGNTO)
                continue

            # decode ifaddrmsg as in if_addr.h
            ifa_family, _, ifa_flags, ifa_scope, ifa_idx = struct.unpack_from(IFADDR_MSG_DEF, buf, offset)
            if ((ifa_flags & IFA_F_DADFAILED) or (ifa_flags & IFA_F_HOMEADDRESS)
                    or (ifa_flags & IFA_F_DEPRECATED) or (ifa_flags & IFA_F_TENTATIVE)):
                logger.debug('ignore address with invalid state {}'.format(hex(ifa_flags)))
                offset += align_to(msg_len, NLM_HDR_ALIGNTO)
                continue

            logger.debug('RTM new/del addr family: {} flags: {} scope: {} idx: {}'.format(
                         ifa_family, ifa_flags, ifa_scope, ifa_idx))
            addr = None
            i = offset + IFA_MSG_LEN
            while i - offset < msg_len:
                attr_len, attr_type = struct.unpack_from('HH', buf, i)
                logger.debug('rt_attr {} {}'.format(attr_len, attr_type))

                if attr_len < RTA_LEN:
                    logger.debug('invalid rtm_attr_len. skipping remainder')
                    break

                if attr_type == IFA_LABEL:
                    name, = struct.unpack_from(str(attr_len - 4 - 1) + 's', buf, i + 4)
                    self.add_interface(NetworkInterface(name.decode(), ifa_scope, ifa_idx))
                elif attr_type == IFA_LOCAL and ifa_family == socket.AF_INET:
                    addr = buf[i + 4:i + 4 + 4]
                elif attr_type == IFA_ADDRESS and ifa_family == socket.AF_INET6:
                    addr = buf[i + 4:i + 4 + 16]
                elif attr_type == IFA_FLAGS:
                    _, ifa_flags = struct.unpack_from('HI', buf, i)
                i += align_to(attr_len, RTA_ALIGNTO)

            if addr is None:
                logger.debug('no address in RTM message')
                offset += align_to(msg_len, NLM_HDR_ALIGNTO)
                continue

            # In case of IPv6 only addresses, there appears to be no IFA_LABEL
            # message. Therefore, the name is requested by other means (#94)
            if ifa_idx not in self.interfaces:
                try:
                    logger.debug('unknown interface name for idx {}. resolving manually'.format(ifa_idx))
                    if_name = socket.if_indextoname(ifa_idx)
                    self.add_interface(NetworkInterface(if_name, ifa_scope, ifa_idx))
                except OSError:
                    logger.exception('interface detection failed')
                    # accept this exception (which should not occur)
                    pass

            # In case really strange things happen and we could not find out the
            # interface name for the returned ifa_idx, we... log a message.
            if ifa_idx in self.interfaces:
                address = NetworkAddress(ifa_family, addr, self.interfaces[ifa_idx])
                if h_type == self.RTM_NEWADDR:
                    self.handle_new_address(address)
                elif h_type == self.RTM_DELADDR:
                    self.handle_deleted_address(address)
            else:
                logger.debug('unknown interface index: {}'.format(ifa_idx))

            offset += align_to(msg_len, NLM_HDR_ALIGNTO)

    def cleanup(self) -> None:
        self.aio_loop.remove_reader(self.socket.fileno())
        self.socket.close()
        super().cleanup()


# from sys/net/route.h
RTA_IFA: int = 0x20

# from sys/socket.h
CTL_NET: int = 4
NET_RT_IFLIST: int = 3

# from sys/net/if.h
IFF_LOOPBACK: int = 0x8
IFF_MULTICAST: int = 0x800 if platform.system() != 'OpenBSD' else 0x8000

# sys/netinet6/in6_var.h
IN6_IFF_TENTATIVE: int = 0x02
IN6_IFF_DUPLICATED: int = 0x04
IN6_IFF_NOTREADY: int = IN6_IFF_TENTATIVE | IN6_IFF_DUPLICATED

SA_ALIGNTO: int = ctypes.sizeof(ctypes.c_long) if platform.system() != "Darwin" else ctypes.sizeof(ctypes.c_uint32)


class RouteSocketAddressMonitor(NetworkAddressMonitor):
    """
    Implementation of the AddressMonitor for FreeBSD and Darwin using route sockets
    """

    # Common definition for beginning part of if(m?a)?_msghdr structs (see net/if.h/man 4 route).
    IF_COMMON_HDR_DEF = '@HBBii' if platform.system() != 'OpenBSD' else '@HBBHHHBBiii'

    # from net/if.h
    RTM_NEWADDR: int = 0xC
    RTM_DELADDR: int = 0xD
    # not tested for OpenBSD
    RTM_IFINFO: int = 0xE

    # from route.h (value equals for FreeBSD, Darwin and OpenBSD)
    RTM_VERSION: int = 0x5

    # from net/if.h (struct ifa_msghdr)
    IFA_MSGHDR_DEF: str = IF_COMMON_HDR_DEF + ('hi' if platform.system() != 'OpenBSD' else '')
    IFA_MSGHDR_SIZE: int = struct.calcsize(IFA_MSGHDR_DEF)

    # The struct package does not allow to specify those, thus we hard code them as chars (x4).
    IF_MSG_DEFS: Dict[str, str] = {
        # if_data in if_msghdr is prepended with an u_short _ifm_spare1, thus the 'H' a the beginning)
        'FreeBSD': 'hH6c2c8c8c104c8c16c',
        # There are 8 bytes and 22 uint32_t in the if_data struct (22 x 4 Bytes + 8 = 96 Bytes)
        # It is also aligned on 4-byte boundary necessitating 2 bytes padding inside if_msghdr
        'Darwin': 'h2c8c22I',
        # struct if_data from /src/sys/net/if.h for if_msghdr
        #  (includes struct timeval which is a int64 + long
        'OpenBSD': '4c3I13Q1Iql'
    }

    socket: socket.socket
    intf_blacklist: List[str]

    is_openbsd: bool = False

    def __init__(self, aio_loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(aio_loop)
        self.intf_blacklist = []

        # Create routing socket to get notified about future changes.
        # Do this before fetching the current routing information to avoid race condition.
        self.socket = socket.socket(socket.AF_ROUTE, socket.SOCK_RAW, socket.AF_UNSPEC)
        self.aio_loop.add_reader(self.socket.fileno(), self.handle_change)

        self.IF_MSGHDR_SIZE = struct.calcsize(self.IF_COMMON_HDR_DEF + self.IF_MSG_DEFS[platform.system()])
        self.is_openbsd = platform.system() == 'OpenBSD'

    def do_enumerate(self) -> None:
        super().do_enumerate()
        mib = [CTL_NET, socket.AF_ROUTE, 0, 0, NET_RT_IFLIST, 0]
        rt_mib = (ctypes.c_int * len(mib))()
        rt_mib[:] = [ctypes.c_int(m) for m in mib]

        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

        # Ask kernel for routing table size first.
        rt_size = ctypes.c_size_t()
        if libc.sysctl(ctypes.byref(rt_mib), ctypes.c_size_t(len(rt_mib)), 0, ctypes.byref(rt_size), 0, 0):
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

        # Get the initial routing (interface list) data.
        rt_buf = ctypes.create_string_buffer(rt_size.value)
        if libc.sysctl(ctypes.byref(rt_mib), ctypes.c_size_t(len(rt_mib)), rt_buf, ctypes.byref(rt_size), 0, 0):
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

        self.parse_route_socket_response(rt_buf.raw, True)

    def handle_change(self) -> None:
        super().handle_change()

        self.parse_route_socket_response(self.socket.recv(4096), False)

    def parse_route_socket_response(self, buf: bytes, keep_intf: bool) -> None:
        offset = 0

        intf = None
        intf_flags = 0
        while offset < len(buf):
            # unpack route message response
            if not self.is_openbsd:
                rtm_len, rtm_version, rtm_type, addr_mask, flags = struct.unpack_from(
                    self.IF_COMMON_HDR_DEF, buf, offset)
            else:
                rtm_len, rtm_version, rtm_type, ifa_hdr_len, _, _, _, _, addr_mask, flags, _ = struct.unpack_from(
                    self.IF_COMMON_HDR_DEF, buf, offset)

            # exit condition for OpenBSD where always the complete buffer (ie 4096 bytes) is returned
            if rtm_len == 0:
                break

            # skip over non-understood packets and versions
            if (rtm_type not in [self.RTM_NEWADDR, self.RTM_DELADDR, self.RTM_IFINFO]) or (
                    rtm_version != self.RTM_VERSION):
                offset += rtm_len
                continue

            if rtm_type == self.RTM_IFINFO:
                intf_flags = flags

            sa_offset = offset + (self.IF_MSGHDR_SIZE if rtm_type == self.RTM_IFINFO else self.IFA_MSGHDR_SIZE)

            # For a route socket message, and different to a sysctl response,
            # the link info is stored inside the same rtm message, so it has to
            # survive multiple rtm messages in such cases
            if not keep_intf:
                intf = None

            new_intf = self.parse_addrs(buf, sa_offset, offset + rtm_len, intf, addr_mask, rtm_type, intf_flags)
            intf = new_intf if new_intf else intf

            offset += rtm_len

    def clear_addr_scope(self, raw_addr: bytes) -> bytes:
        addr: bytearray = bytearray(raw_addr)
        # adapted from in6_clearscope BSD/Mac kernel method (see scope6.c)
        if addr[0] == 0xfe and (addr[1] & 0xc0) == 0x80:
            addr[2] = 0
            addr[3] = 0

        return bytes(addr)

    def parse_addrs(self, buf: bytes, offset: int, limit: int, intf: Optional[NetworkInterface], addr_mask: int,
                    rtm_type: int, flags: int) -> Optional[NetworkInterface]:
        addr_type_idx = 1
        addr = None
        addr_family: int = socket.AF_UNSPEC
        while offset < limit:
            while not (addr_type_idx & addr_mask) and (addr_type_idx <= addr_mask):
                addr_type_idx = addr_type_idx << 1

            sa_len, sa_fam = struct.unpack_from('@BB', buf, offset)
            if sa_fam in [socket.AF_INET, socket.AF_INET6] and addr_type_idx == RTA_IFA:
                addr_family = sa_fam
                addr_offset = 4 if sa_fam == socket.AF_INET else 8
                addr_length = 4 if sa_fam == socket.AF_INET else 16
                addr_start = offset + addr_offset
                addr = buf[addr_start:addr_start + addr_length]
                if sa_fam == socket.AF_INET6:
                    addr = self.clear_addr_scope(addr)
            elif sa_fam == socket.AF_LINK:
                idx, _, name_len = struct.unpack_from('@HBB', buf, offset + 2)
                if idx > 0:
                    off_name = offset + 8
                    if_name = (buf[off_name:off_name + name_len]).decode()
                    intf = self.add_interface(NetworkInterface(if_name, idx, idx))

            offset += align_to(sa_len, SA_ALIGNTO) if sa_len > 0 else SA_ALIGNTO
            addr_type_idx = addr_type_idx << 1

        if rtm_type == self.RTM_IFINFO and intf is not None:
            if flags & IFF_LOOPBACK or not flags & IFF_MULTICAST:
                self.intf_blacklist.append(intf.name)
            elif intf.name in self.intf_blacklist:
                self.intf_blacklist.remove(intf.name)

        if intf is None or intf.name in self.intf_blacklist or addr is None:
            return intf

        address = NetworkAddress(addr_family, addr, intf)
        if rtm_type == self.RTM_DELADDR:
            self.handle_deleted_address(address)
        else:
            # Too bad, the address may be unuseable (tentative, e.g.) here
            # but we won't get any further notifcation about the address being
            # available for use. Thus, we try and may fail here
            self.handle_new_address(address)

        return intf

    def cleanup(self) -> None:
        self.aio_loop.remove_reader(self.socket.fileno())
        self.socket.close()
        super().cleanup()


class DladmAddressMonitor(NetworkAddressMonitor):

    class sockaddr(ctypes.Structure):
        _fields_ = [("family", ctypes.c_ushort),
                    ("dummy", ctypes.c_ushort),
                    ("data", ctypes.c_ubyte * 14)]

    class ifaddrs(ctypes.Structure):
        pass

    ifaddrs._fields_ = [("next", ctypes.POINTER(ifaddrs)),
                        ("name", ctypes.c_char_p),
                        ("flags", ctypes.c_ulonglong),
                        ("addr", ctypes.POINTER(sockaddr)),
                        ("netmask", ctypes.POINTER(sockaddr)),
                        ("dstaddr", ctypes.POINTER(sockaddr)),
                        ("data", ctypes.c_void_p)]

    def freeifaddrs(self, ifa) -> None:
        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
        while ifa.next:
            curr = ifa
            ifa = ifa.next[0]
            libc.free(curr.name)
            libc.free(curr.addr)
            libc.free(curr.netmask)
            libc.free(curr.dstaddr)
            libc.free(curr.data)
            del curr

    def do_enumerate(self) -> None:
        super().do_enumerate()
        libsocket = ctypes.CDLL(ctypes.util.find_library('socket'), use_errno=True)
        ifas = self.ifaddrs()
        if libsocket.getifaddrs(ctypes.byref(ifas)) == 0:
            ifa = ifas
            ifa_idx = 0
            while ifa.next:
                if ifa.name:
                    logger.debug("{}%{}".format(
                        socket.inet_ntop(ifa.addr[0].family, bytes(ifa.addr[0].data[:4])),
                        ifa.name.decode()))
                    addr = socket.inet_ntop(ifa.addr[0].family, bytes(ifa.addr[0].data[:4]))
                    intf = NetworkInterface(ifa.name.decode(), 0, ifa_idx)
                    self.add_interface(intf)
                    self.handle_new_address(NetworkAddress(ifa.addr[0].family, addr, intf))
                    ifa_idx += 1

                ifa = ifa.next[0]
            self.freeifaddrs(ifas)


def sigterm_handler() -> None:
    logger.info('received termination/interrupt signal, tearing down')
    # implictely raise SystemExit to cleanup properly
    sys.exit(0)


def parse_args() -> None:
    global args, logger

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-i', '--interface',
        help='interface or address to use',
        action='append', default=[])
    parser.add_argument(
        '-H', '--hoplimit',
        help='hop limit for multicast packets (default = 1)', type=int,
        default=1)
    parser.add_argument(
        '-U', '--uuid',
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
        # use only the local part of a possible FQDN
        default=socket.gethostname().partition('.')[0])
    parser.add_argument(
        '-w', '--workgroup',
        help='set workgroup name (default WORKGROUP)',
        default='WORKGROUP')
    parser.add_argument(
        '-A', '--no-autostart',
        help='do not start networking after launch',
        action='store_true')
    parser.add_argument(
        '-t', '--no-http',
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
    parser.add_argument(
        '-s', '--shortlog',
        help='log only level and message',
        action='store_true')
    parser.add_argument(
        '-p', '--preserve-case',
        help='preserve case of the provided/detected hostname',
        action='store_true')
    parser.add_argument(
        '-c', '--chroot',
        help='directory to chroot into',
        default=None)
    parser.add_argument(
        '-u', '--user',
        help='drop privileges to user:group',
        default=None)
    parser.add_argument(
        '-D', '--discovery',
        help='enable discovery operation mode',
        action='store_true')
    parser.add_argument(
        '-l', '--listen',
        help='listen on path or localhost port in discovery mode',
        default=None)
    parser.add_argument(
        '-o', '--no-host',
        help='disable server mode operation (host will be undiscoverable)',
        action='store_true')
    parser.add_argument(
        '-V', '--version',
        help='show version number and exit',
        action='store_true')
    parser.add_argument(
        '--metadata-timeout',
        help='set timeout for HTTP-based metadata exchange',
        default=2.0)
    parser.add_argument(
        '--source-port',
        help='send multicast traffic/receive replies on this port',
        type=int,
        default=0)

    args = parser.parse_args(sys.argv[1:])

    if args.version:
        print('wsdd - Web Service Discovery Daemon, v{}'.format(WSDD_VERSION))
        sys.exit(0)

    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose > 1:
        log_level = logging.DEBUG
        asyncio.get_event_loop().set_debug(True)
        logging.getLogger("asyncio").setLevel(logging.DEBUG)
    else:
        log_level = logging.WARNING

    if args.shortlog:
        fmt = '%(levelname)s: %(message)s'
    else:
        fmt = '%(asctime)s:%(name)s %(levelname)s(pid %(process)d): %(message)s'

    logging.basicConfig(level=log_level, format=fmt)
    logger = logging.getLogger('wsdd')

    if not args.interface:
        logger.warning('no interface given, using all interfaces')

    if not args.uuid:
        def read_uuid_from_file(fn: str) -> Union[None, uuid.UUID]:
            try:
                with open(fn) as f:
                    s: str = f.readline().strip()
                    return uuid.UUID(s)
            except Exception:
                return None

        # machine uuid: try machine-id file first but also check for hostid (FreeBSD)
        args.uuid = read_uuid_from_file('/etc/machine-id') or \
            read_uuid_from_file('/etc/hostid') or \
            uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname())

        logger.info('using pre-defined UUID {0}'.format(str(args.uuid)))
    else:
        args.uuid = uuid.UUID(args.uuid)
        logger.info('user-supplied device UUID is {0}'.format(str(args.uuid)))

    for prefix, uri in namespaces.items():
        ElementTree.register_namespace(prefix, uri)


def chroot(root: str) -> bool:
    """
    Chroot into a separate directory to isolate ourself for increased security.
    """
    # preload for socket.gethostbyaddr()
    import encodings.idna

    try:
        os.chroot(root)
        os.chdir('/')
        logger.info('chrooted successfully to {}'.format(root))
    except Exception as e:
        logger.error('could not chroot to {}: {}'.format(root, e))
        return False

    return True


def get_ids_from_userspec(user_spec: str) -> Tuple[int, int]:
    uid: int
    gid: int
    try:
        user, _, group = user_spec.partition(':')

        if user:
            uid = pwd.getpwnam(user).pw_uid

        if group:
            gid = grp.getgrnam(group).gr_gid
    except Exception as e:
        raise RuntimeError('could not get uid/gid for {}: {}'.format(user_spec, e))

    return (uid, gid)


def drop_privileges(uid: int, gid: int) -> bool:
    try:
        if gid is not None:
            os.setgid(gid)
            os.setegid(gid)
            logger.debug('switched uid to {}'.format(uid))

        if uid is not None:
            os.setuid(uid)
            os.seteuid(uid)
            logger.debug('switched gid to {}'.format(gid))

        logger.info('running as {} ({}:{})'.format(args.user, uid, gid))
    except Exception as e:
        logger.error('dropping privileges failed: {}'.format(e))
        return False

    return True


def create_address_monitor(system: str, aio_loop: asyncio.AbstractEventLoop) -> NetworkAddressMonitor:
    if system == 'Linux':
        return NetlinkAddressMonitor(aio_loop)
    elif system in ['FreeBSD', 'Darwin', 'OpenBSD']:
        return RouteSocketAddressMonitor(aio_loop)
    elif system == 'SunOS':
        return DladmAddressMonitor(aio_loop)
    else:
        raise NotImplementedError('unsupported OS: ' + system)


def main() -> int:
    global logger, args  # noqa: F824

    parse_args()

    if args.ipv4only and args.ipv6only:
        logger.error('Listening to no IP address family.')
        return 4

    aio_loop = asyncio.new_event_loop()
    nm = create_address_monitor(platform.system(), aio_loop)

    api_server = None
    if args.listen:
        api_server = ApiServer(aio_loop, args.listen, nm)
    elif 'systemd' in sys.modules:
        fds = systemd.daemon.listen_fds()
        if fds:
            api_server = ApiServer(aio_loop, socket.socket(fileno=fds[0]), nm)

    # get uid:gid before potential chroot'ing
    if args.user is not None:
        ids = get_ids_from_userspec(args.user)
        if not ids:
            return 3

    if args.chroot is not None:
        if not chroot(args.chroot):
            return 2

    if args.user is not None:
        if not drop_privileges(ids[0], ids[1]):
            return 3

    if args.chroot and (os.getuid() == 0 or os.getgid() == 0):
        logger.warning('chrooted but running as root, consider -u option')

    # main loop, serve requests coming from any outbound socket
    aio_loop.add_signal_handler(signal.SIGINT, sigterm_handler)
    aio_loop.add_signal_handler(signal.SIGTERM, sigterm_handler)
    try:
        aio_loop.run_forever()
    except (SystemExit, KeyboardInterrupt):
        logger.info('shutting down gracefully...')
        if api_server is not None:
            aio_loop.run_until_complete(api_server.cleanup())

        nm.cleanup()
        aio_loop.stop()
    except Exception:
        logger.exception('error in main loop')

    logger.info('Done.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
