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
# (c) Steffen Christgau, 2017-2019

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
import http
import http.server
import urllib.request
import urllib.parse
import socketserver
import os
import pwd
import grp
import datetime


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


class MulticastInterface:
    """
    A class for handling multicast traffic on a given interface for a
    given address family. It provides multicast sender and receiver sockets
    """
    def __init__(self, family, address, intf_name, selector):
        self.address = address
        self.family = family
        self.name = intf_name
        self.recv_socket = socket.socket(self.family, socket.SOCK_DGRAM)
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.send_socket = socket.socket(self.family, socket.SOCK_DGRAM)
        self.transport_address = address
        self.multicast_address = None
        self.listen_address = None

        self.message_handlers = {}
        self.selector = selector

        if family == socket.AF_INET:
            self.init_v4()
        elif family == socket.AF_INET6:
            self.init_v6()

        logger.info('joined multicast group {0} on {2}%{1}'.format(
            self.multicast_address, self.name, self.address))
        logger.debug('transport address on {0} is {1}'.format(
            self.name, self.transport_address))
        logger.debug('will listen for HTTP traffic on address {0}'.format(
            self.listen_address))

        self.selector.register(self.recv_socket, selectors.EVENT_READ, self)
        self.selector.register(self.send_socket, selectors.EVENT_READ, self)

    def init_v6(self):
        idx = socket.if_nametoindex(self.name)
        self.multicast_address = (WSD_MCAST_GRP_V6, WSD_UDP_PORT, 0x575C, idx)

        # v6: member_request = { multicast_addr, intf_idx }
        mreq = (
            socket.inet_pton(self.family, WSD_MCAST_GRP_V6) +
            struct.pack('@I', idx))
        self.recv_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        self.recv_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        # bind to network interface, i.e. scope and handle OS differences,
        # see Stevens: Unix Network Programming, Section 21.6, last paragraph
        try:
            self.recv_socket.bind((WSD_MCAST_GRP_V6, WSD_UDP_PORT, 0, idx))
        except OSError:
            self.recv_socket.bind(('::', 0, 0, idx))

        self.send_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        self.send_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, args.hoplimit)
        self.send_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)

        self.transport_address = '[{0}]'.format(self.address)
        self.listen_address = (self.address, WSD_HTTP_PORT, 0, idx)

    def init_v4(self):
        idx = socket.if_nametoindex(self.name)
        self.multicast_address = (WSD_MCAST_GRP_V4, WSD_UDP_PORT)

        # v4: member_request (ip_mreqn) = { multicast_addr, intf_addr, idx }
        mreq = (
            socket.inet_pton(self.family, WSD_MCAST_GRP_V4) +
            socket.inet_pton(self.family, self.address) +
            struct.pack('@I', idx))
        self.recv_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        try:
            self.recv_socket.bind((WSD_MCAST_GRP_V4, WSD_UDP_PORT))
        except OSError:
            self.recv_socket.bind(('', WSD_UDP_PORT))

        self.send_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
        self.send_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        self.send_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, args.hoplimit)

        self.listen_address = (self.address, WSD_HTTP_PORT)

    def add_handler(self, socket, handler):
        try:
            self.selector.register(socket, selectors.EVENT_READ, self)
        except KeyError:
            # accept attempts of multiple registrations
            pass

        if socket in self.message_handlers:
            self.message_handlers[socket].append(handler)
        else:
            self.message_handlers[socket] = [handler]

    def remove_handler(self, socket, handler):
        if socket in self.message_handlers:
            if handler in self.message_handlers[socket]:
                self.message_handlers[socket].remove(handler)

    def handle_request(self, key):
        s = None
        if key.fileobj == self.send_socket:
            s = self.send_socket
        elif key.fileobj == self.recv_socket:
            s = self.recv_socket
        else:
            return

        msg, address = s.recvfrom(WSD_MAX_LEN)
        if s in self.message_handlers:
            for handler in self.message_handlers[s]:
                handler.handle_request(msg, address)


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

MIME_TYPE_SOAP_XML = 'application/soap+xml'

# protocol assignments (WSD spec/Section 2.4)
WSD_UDP_PORT = 3702
WSD_HTTP_PORT = 5357
WSD_MAX_LEN = 32767

WSDD_LISTEN_PORT = 5359

# SOAP/UDP transmission constants
MULTICAST_UDP_REPEAT = 4
UNICAST_UDP_REPEAT = 2
UDP_MIN_DELAY = 50
UDP_MAX_DELAY = 250
UDP_UPPER_DELAY = 500

# servers must recond in 4 seconds after probe arrives
PROBE_TIMEOUT = 4
MAX_STARTUP_PROBE_DELAY = 3

# some globals
wsd_instance_id = int(time.time())
send_queue = []

args = None
logger = None


class WSDMessageHandler(object):
    known_messages = collections.deque([], WSD_MAX_KNOWN_MESSAGES)

    def __init__(self):
        self.handlers = {}

    # shortcuts for building WSD responses
    def add_endpoint_reference(self, parent, endpoint=None):
        epr = ElementTree.SubElement(parent, 'wsa:EndpointReference')
        address = ElementTree.SubElement(epr, 'wsa:Address')
        if endpoint is None:
            address.text = args.uuid.urn
        else:
            address.text = endpoint

    def add_metadata_version(self, parent):
        meta_data = ElementTree.SubElement(parent, 'wsd:MetadataVersion')
        meta_data.text = '1'

    def add_types(self, parent):
        dev_type = ElementTree.SubElement(parent, 'wsd:Types')
        dev_type.text = WSD_TYPE_DEVICE_COMPUTER

    def add_xaddr(self, parent, transport_addr):
        if transport_addr:
            item = ElementTree.SubElement(parent, 'wsd:XAddrs')
            item.text = 'http://{0}:{1}/{2}'.format(
                transport_addr, WSD_HTTP_PORT, args.uuid)

    def build_message(self, to_addr, action_str, request_header, response):
        retval = self.xml_to_buffer(self.build_message_tree(
            to_addr, action_str, request_header, response)[0])

        logger.debug('constructed xml for WSD message: {0}'.format(retval))

        return retval

    def build_message_tree(self, to_addr, action_str, request_header, body):
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

        if request_header:
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

    def add_header_elements(self, header, extra):
        pass

    def handle_message(self, msg, interface, src_address):
        """
        handle a WSD message that might be received by a MulticastInterface
        """
        tree = ElementTree.fromstring(msg)
        header = tree.find('./soap:Header', namespaces)
        msg_id = header.find('./wsa:MessageID', namespaces).text

        # if message came over multicast interface, check for duplicates
        if interface and self.is_duplicated_msg(msg_id):
            logger.debug('known message ({0}): dropping it'.format(msg_id))
            return None

        response = None
        action = header.find('./wsa:Action', namespaces).text
        body = tree.find('./soap:Body', namespaces)
        _, _, action_method = action.rpartition('/')

        if interface:
            logger.info('{}:{}({}) - - "{} {} UDP" - -'.format(
                src_address[0], src_address[1], interface.name,
                action_method, msg_id
            ))
        else:
            # http logging is already done by according server
            logger.debug('processing WSD {} message ({})'.format(
                action_method, msg_id))

        logger.debug('incoming message content is {0}'.format(msg))
        if action in self.handlers:
            handler = self.handlers[action]
            retval = handler(header, body)
            if retval is not None:
                response, response_type = retval
                return self.build_message(
                    WSA_ANON, response_type, header, response)
        else:
            logger.debug('unhandled action {0}/{1}'.format(action, msg_id))

        return None

    def is_duplicated_msg(self, msg_id):
        """
        Check for a duplicated message.

        Implements SOAP-over-UDP Appendix II Item 2
        """
        if msg_id in type(self).known_messages:
            return True

        type(self).known_messages.append(msg_id)

        return False

    def xml_to_buffer(self, xml):
        retval = b'<?xml version="1.0" encoding="utf-8"?>'
        retval = retval + ElementTree.tostring(xml, encoding='utf-8')

        return retval


class WSDUDPMessageHandler(WSDMessageHandler):

    def __init__(self, interface):
        super().__init__()

        self.interface = interface

    def startup(self):
        pass

    def teardown(self):
        pass

    def enqueue_datagram(self, msg, address=None, msg_type=None):
        """
        Add an outgoing WSD (SOAP) message to the queue of outstanding messages

        Implements SOAP over UDP, Appendix I.
        """
        if not address:
            address = self.interface.multicast_address

        if msg_type:
            logger.debug('scheduling {0} message via {1} to {2}'.format(
                msg_type, self.interface.name, address))

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


class WSDDiscoveredDevice(object):

    def __init__(self, xml_str, xaddr, interface):
        self.last_seen = None
        self.addresses = {}
        self.props = {}

        self.update(xml_str, xaddr, interface)

    def update(self, xml_str, xaddr, interface):
        tree = ElementTree.fromstring(xml_str)
        mds_path = 'soap:Body/wsx:Metadata/wsx:MetadataSection'
        sections = tree.findall(mds_path, namespaces)
        for section in sections:
            dialect = section.attrib['Dialect']
            if dialect == WSDP_URI + '/ThisDevice':
                self.extract_wsdp_props(section, self.props, dialect)
            elif dialect == WSDP_URI + '/ThisModel':
                self.extract_wsdp_props(section, self.props, dialect)
            elif dialect == WSDP_URI + '/Relationship':
                host_xpath = ('wsdp:Relationship[@Type="{}/host"]/wsdp:Host'
                              .format(WSDP_URI))
                host_sec = section.find(host_xpath, namespaces)
                if (host_sec):
                    self.extract_host_props(host_sec, self.props)
            else:
                logger.debug('unknown metadata dialect ({})'.format(dialect))

        url = urllib.parse.urlparse(xaddr)
        addr, _, _ = url.netloc.rpartition(':')
        if interface not in self.addresses:
            self.addresses[interface] = set([addr])
        else:
            self.addresses[interface].add(addr)

        self.last_seen = time.time()
        logger.info('discovered {} in {} on {}%{}'.format(
            self.props['DisplayName'], self.props['BelongsTo'], addr,
            interface.name))
        logger.debug(str(self.props))

    def extract_wsdp_props(self, root, target_dict, dialect):
        _, _, propsRoot = dialect.rpartition('/')
        # XPath support is limited, so filter by namespace on our own
        nodes = root.findall('./wsdp:{0}/*'.format(propsRoot), namespaces)
        ns_prefix = '{{{}}}'.format(WSDP_URI)
        prop_nodes = [n for n in nodes if n.tag.startswith(ns_prefix)]
        for node in prop_nodes:
            tag_name = node.tag[len(ns_prefix):]
            target_dict[tag_name] = node.text

    def extract_host_props(self, root, target_dict):
        types = root.findtext('wsdp:Types', '', namespaces)
        target_dict['types'] = types.split(' ')
        if types != PUB_COMPUTER:
            return

        comp = root.findtext(PUB_COMPUTER, '', namespaces)
        target_dict['DisplayName'], _, target_dict['BelongsTo'] = (
            comp.partition('/'))


class WSDClient(WSDUDPMessageHandler):

    def __init__(self, interface, known_devices):
        super().__init__(interface)

        self.interface.add_handler(self.interface.send_socket, self)
        self.interface.add_handler(self.interface.recv_socket, self)

        self.probes = {}
        self.known_devices = known_devices

        self.handlers[WSD_HELLO] = self.handle_hello
        self.handlers[WSD_BYE] = self.handle_bye
        self.handlers[WSD_PROBE_MATCH] = self.handle_probe_match
        self.handlers[WSD_RESOLVE_MATCH] = self.handle_resolve_match

    def send_probe(self):
        """WS-Discovery, Section 4.3, Probe message"""
        self.remove_outdated_probes()

        probe = ElementTree.Element('wsd:Probe')
        ElementTree.SubElement(probe, 'wsd:Types').text = WSD_TYPE_DEVICE

        xml, i = self.build_message_tree(WSA_DISCOVERY, WSD_PROBE, None, probe)
        self.enqueue_datagram(self.xml_to_buffer(xml), msg_type='Probe')
        self.probes[i] = time.time()

    def startup(self):
        # avoid packet storm when hosts come up by delaying initial probe
        time.sleep(random.randint(0, MAX_STARTUP_PROBE_DELAY))
        self.send_probe()

    def teardown(self):
        self.remove_outdated_probes()

    def handle_request(self, msg, address):
        self.handle_message(msg, self.interface, address)

    def handle_hello(self, header, body):
        pm_path = 'wsd:Hello'
        endpoint, xaddrs = self.extract_endpoint_metadata(body, pm_path)
        if not xaddrs:
            logger.info('Hello without XAddrs, sending resolve')
            msg = self.build_resolve_message(endpoint)
            self.enqueue_datagram(msg)
            return

        xaddr = xaddrs.strip()
        logger.info('Hello from {} on {}'.format(endpoint, xaddr))
        self.perform_metadata_exchange(endpoint, xaddr)

    def handle_bye(self, header, body):
        bye_path = 'wsd:Bye'
        endpoint, _ = self.extract_endpoint_metadata(body, bye_path)
        device_uuid = str(uuid.UUID(endpoint))
        if device_uuid in self.known_devices:
            del(self.known_devices[device_uuid])

    def handle_probe_match(self, header, body):
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
            msg = self.build_resolve_message(endpoint)
            self.enqueue_datagram(msg)
            return

        xaddr = xaddrs.strip()
        logger.debug('probe match for {} on {}'.format(endpoint, xaddr))
        self.perform_metadata_exchange(endpoint, xaddr)

    def build_resolve_message(self, endpoint):
        resolve = ElementTree.Element('wsd:Resolve')
        self.add_endpoint_reference(resolve, endpoint)

        return self.build_message(WSA_DISCOVERY, WSD_RESOLVE, None, resolve)

    def handle_resolve_match(self, header, body):
        rm_path = 'wsd:ResolveMatches/wsd:ResolveMatch'
        endpoint, xaddrs = self.extract_endpoint_metadata(body, rm_path)
        if not endpoint or not xaddrs:
            logger.warning('resolve match without endpoint/xaddr')
            return

        xaddr = xaddrs.strip()
        logger.debug('resolve match for {} on {}'.format(endpoint, xaddr))
        self.perform_metadata_exchange(endpoint, xaddr)

    def extract_endpoint_metadata(self, body, prefix):
        prefix = prefix + '/'
        addr_path = 'wsa:EndpointReference/wsa:Address'

        endpoint = body.findtext(prefix + addr_path, namespaces=namespaces)
        xaddrs = body.findtext(prefix + 'wsd:XAddrs', namespaces=namespaces)

        return endpoint, xaddrs

    def perform_metadata_exchange(self, endpoint, xaddr):
        if not (xaddr.startswith('http://') or xaddr.startswith('https://')):
            logger.debug('invalid XAddr: {}'.format(xaddr))
            return

        host = None
        url = xaddr
        if self.interface.family == socket.AF_INET6:
            host = '[{}]'.format(url.partition('[')[2].partition(']')[0])
            url = url.replace(']', '%{}]'.format(self.interface.name))

        body = self.build_getmetadata_message(endpoint)
        request = urllib.request.Request(url, data=body, method='POST')
        request.add_header('Content-Type', 'application/soap+xml')
        request.add_header('User-Agent', 'wsdd')
        if host is not None:
            request.add_header('Host', host)

        try:
            with urllib.request.urlopen(request, None, 2.0) as stream:
                self.handle_metadata(stream.read(), endpoint, xaddr)
        except urllib.error.URLError as e:
            logger.warn('could not fetch metadata from: {}'.format(url, e))

    def build_getmetadata_message(self, endpoint):
        tree, _ = self.build_message_tree(endpoint, WSD_GET, None, None)
        return self.xml_to_buffer(tree)

    def handle_metadata(self, meta, endpoint, xaddr):
        device_uuid = str(uuid.UUID(endpoint))
        if device_uuid in self.known_devices:
            self.known_devices[device_uuid].update(meta, xaddr, self.interface)
        else:
            self.known_devices[device_uuid] = WSDDiscoveredDevice(
                    meta, xaddr, self.interface)

    def remove_outdated_probes(self):
        cut = time.time() - PROBE_TIMEOUT * 2
        self.probes = dict(filter(lambda x: x[1] > cut, self.probes.items()))

    def add_header_elements(self, header, extra):
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

    message_number = 0

    def __init__(self, interface):
        super().__init__(interface)

        self.interface.add_handler(self.interface.recv_socket, self)

        self.handlers[WSD_PROBE] = self.handle_probe
        self.handlers[WSD_RESOLVE] = self.handle_resolve

    def startup(self):
        self.send_hello()

    def teardown(self):
        self.send_bye()

    def handle_request(self, msg, address):
        reply = self.handle_message(msg, self.interface, address)
        if reply:
            self.enqueue_datagram(reply, address=address)

    def send_hello(self):
        """WS-Discovery, Section 4.1, Hello message"""
        hello = ElementTree.Element('wsd:Hello')
        self.add_endpoint_reference(hello)
        # THINK: Microsoft does not send the transport address here due
        # to privacy reasons. Could make this optional.
        self.add_xaddr(hello, self.interface.transport_address)
        self.add_metadata_version(hello)

        msg = self.build_message(WSA_DISCOVERY, WSD_HELLO, None, hello)
        self.enqueue_datagram(msg, msg_type='Hello')

    def send_bye(self):
        """WS-Discovery, Section 4.2, Bye message"""
        bye = ElementTree.Element('wsd:Bye')
        self.add_endpoint_reference(bye)

        msg = self.build_message(WSA_DISCOVERY, WSD_BYE, None, bye)
        self.enqueue_datagram(msg, msg_type='Bye')

    def handle_probe(self, header, body):
        probe = body.find('./wsd:Probe', namespaces)
        scopes = probe.find('./wsd:Scopes', namespaces)

        if scopes:
            # THINK: send fault message (see p. 21 in WSD)
            logger.warning('scopes ({}) unsupported but probed'.format(scopes))
            return None, None

        types_elem = probe.find('./wsd:Types', namespaces)
        if types_elem is None:
            logger.debug('Probe message lacks wsd:Types element. Ignored.')
            return None, None

        types = types_elem.text
        if not types == WSD_TYPE_DEVICE:
            logger.debug('unknown discovery type ({}) for probe'.format(types))
            return None, None

        matches = ElementTree.Element('wsd:ProbeMatches')
        match = ElementTree.SubElement(matches, 'wsd:ProbeMatch')
        self.add_endpoint_reference(match)
        self.add_types(match)
        self.add_metadata_version(match)

        return matches, WSD_PROBE_MATCH

    def handle_resolve(self, header, body):
        resolve = body.find('./wsd:Resolve', namespaces)
        addr = resolve.find('./wsa:EndpointReference/wsa:Address', namespaces)
        if addr is None:
            logger.debug('invalid resolve request: missing endpoint address')
            return None, None

        if not addr.text == args.uuid.urn:
            logger.debug(
                'invalid resolve request: address ({}) does not '
                'match own one ({})'.format(addr.text, args.uuid.urn))
            return None, None

        matches = ElementTree.Element('wsd:ResolveMatches')
        match = ElementTree.SubElement(matches, 'wsd:ResolveMatch')
        self.add_endpoint_reference(match)
        self.add_types(match)
        self.add_xaddr(match, addr)
        self.add_metadata_version(match)

        return matches, WSD_RESOLVE_MATCH

    def add_header_elements(self, header, extra):
        ElementTree.SubElement(header, 'wsd:AppSequence', {
            'InstanceId': str(wsd_instance_id),
            'SequenceId': uuid.uuid1().urn,
            'MessageNumber': str(type(self).message_number)})

        type(self).message_number += 1


class WSDHttpMessageHandler(WSDMessageHandler):

    def __init__(self):
        super().__init__()

        self.handlers[WSD_GET] = self.handle_get

    def handle_get(self, header, body):
        # see https://msdn.microsoft.com/en-us/library/hh441784.aspx for an
        # example. Some of the properties below might be made configurable
        # in future releases.
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

    def __init__(self, server_address, RequestHandlerClass, addr_family, sel):
        if addr_family == socket.AF_INET6:
            type(self).address_family = addr_family

        self.selector = sel
        self.wsd_handler = WSDHttpMessageHandler()

        super().__init__(server_address, RequestHandlerClass)

    def server_bind(self):
        if type(self).address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        super().server_bind()
        self.selector.register(self.fileno(), selectors.EVENT_READ, self)


class WSDHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    """Class for handling WSD requests coming over HTTP"""

    def log_message(self, fmt, *args):
        logger.info("{} - - ".format(self.address_string()) + fmt % args)

    def do_POST(self):
        if self.path != '/' + str(args.uuid):
            self.send_error()

        ct = self.headers['Content-Type']
        if ct is None or not ct.startswith(MIME_TYPE_SOAP_XML):
            self.send_error(http.HTTPStatus.NOT_FOUND, 'Invalid Content-Type')

        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        response = self.server.wsd_handler.handle_message(body, None, None)
        if response:
            self.send_response(http.HTTPStatus.OK)
            self.send_header('Content-Type', MIME_TYPE_SOAP_XML)
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_error(http.HTTPStatus.BAD_REQUEST)


class ApiRequestHandler(socketserver.StreamRequestHandler):

    def handle(self):
        line = str(self.rfile.readline().strip(), 'utf-8')
        if not line:
            return

        words = line.split()
        command = words[0]
        args = words[1:]
        if command == 'probe':
            intf = args[0] if args else None
            logger.debug('probing devices on {} upon request'.format(intf))
            for client in self.get_clients_by_interface(intf):
                client.send_probe()
        elif command == 'clear':
            logger.debug('clearing list of known devices')
            self.server.wsd_known_devices.clear()
        elif command == 'list':
            self.wfile.write(bytes(self.get_list_reply(), 'utf-8'))
        else:
            logger.debug('could not handle API request: {}'.format(line))

    def get_clients_by_interface(self, interface):
        return [c for c in self.server.wsd_clients if
                c.interface.name == interface or not interface]

    def get_list_reply(self):
        retval = ''
        for dev_uuid in self.server.wsd_known_devices:
            dev = self.server.wsd_known_devices[dev_uuid]
            addrs_str = []
            for mci, addrs in dev.addresses.items():
                addrs_str.append(', '.join(['{}%{}'.format(a, mci.name)
                                 for a in addrs]))

            retval = retval + '{}\t{}\t{}\t{}\t{}\n'.format(
                dev_uuid,
                dev.props['DisplayName'],
                dev.props['BelongsTo'],
                datetime.datetime.fromtimestamp(dev.last_seen).isoformat(
                    'T', 'seconds'),
                ','.join(addrs_str))

        return retval


class ApiServer(object):

    def __init__(self, selector, listen_address, clients, known_devices):
        self.clients = clients

        if isinstance(listen_address, int) or listen_address.isnumeric():
            s_addr = ('localhost', int(listen_address))
            socketserver.TCPServer.allow_reuse_address = True
            s = socketserver.TCPServer(s_addr, ApiRequestHandler)
        else:
            s = socketserver.UnixStreamServer(
                listen_address, ApiRequestHandler)

        # quiet hacky
        s.wsd_clients = clients
        s.wsd_known_devices = known_devices

        selector.register(s.fileno(), selectors.EVENT_READ, s)


def enumerate_host_interfaces():
    """Get all addresses of all installed interfaces except loopbacks"""
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
    addr = ctypes.POINTER(if_addrs)()
    retval = libc.getifaddrs(ctypes.byref(addr))
    if retval:
        raise OSError(ctypes.get_errno())

    IFF_LOOPBACK = 0x8  # common value for Linux, Free/OpenBSD

    addrs = []
    ptr = addr
    while ptr:
        deref = ptr[0]
        family = deref.addr[0].family if deref.addr else None
        dev_name = deref.name.decode()
        if deref.flags & IFF_LOOPBACK != 0:
            logger.debug('ignoring loop-back interface {}'.format(dev_name))
        elif family == socket.AF_INET:
            addrs.append((
                dev_name, family,
                socket.inet_ntop(family, bytes(deref.addr[0].data[2:6]))))
        elif family == socket.AF_INET6:
            if bytes(deref.addr[0].data[6:8]) == b'\xfe\x80':
                addrs.append((
                    dev_name, family,
                    socket.inet_ntop(family, bytes(deref.addr[0].data[6:22]))))

        ptr = deref.next

    libc.freeifaddrs(addr)

    # filter detected addresses by command line arguments,
    if args.ipv4only:
        addrs = [x for x in addrs if x[1] == socket.AF_INET]

    if args.ipv6only:
        addrs = [x for x in addrs if x[1] == socket.AF_INET6]

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

    args = parser.parse_args(sys.argv[1:])

    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose > 1:
        log_level = logging.DEBUG
    else:
        log_level = logging.WARNING

    if args.shortlog:
        fmt = '%(levelname)s: %(message)s'
    else:
        fmt = ('%(asctime)s:%(name)s %(levelname)s(pid %(process)d): '
               '%(message)s')

    logging.basicConfig(level=log_level, format=fmt)
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
    # time jumps forward, multiple outstanding message which have a
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


def chroot(root):
    """
    Chroot into a separate directory to isolate ourself for increased security.
    """
    try:
        os.chroot(root)
        os.chdir('/')
        logger.info('chrooted successfully to {}'.format(root))
    except Exception as e:
        logger.error('could not chroot to {}: {}'.format(root, e))
        return False

    return True


def get_ids_from_userspec(user_spec):
    uid = None
    gid = None
    try:
        user, _, group = user_spec.partition(':')

        if user:
            uid = pwd.getpwnam(user).pw_uid

        if group:
            gid = grp.getgrnam(group).gr_gid
    except Exception as e:
        logger.error('could not get uid/gid for {}: {}'.format(user_spec, e))
        return False

    return (uid, gid)


def drop_privileges(uid, gid):
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


def main():
    """
    Multicast handling: send Hello message on startup, receive from multicast
    sockets and handle the messages, and emit Bye message when process gets
    terminated by signal
    """
    parse_args()

    addresses = enumerate_host_interfaces()
    if not addresses:
        logger.error("No multicast addresses available. Exiting.")
        return 1

    s = selectors.DefaultSelector()
    handlers = []
    clients = []
    known_devices = {}

    for address in addresses:
        interface = MulticastInterface(address[1], address[2], address[0], s)

        if not args.no_host:
            handlers.append(WSDHost(interface))
            if not args.no_http:
                WSDHttpServer(interface.listen_address, WSDHttpRequestHandler,
                              interface.family, s)

        if args.discovery:
            clients.append(WSDClient(interface, known_devices))
            handlers.append(clients[-1])

    if not args.discovery and args.listen:
        logger.warning('Listen option ignored since discovery is disabled.')
    elif args.discovery and not args.listen:
        logger.warning('Discovery enabled but no listen option provided. '
                       'Falling back to port {}'.format(WSDD_LISTEN_PORT))
        args.listen = WSDD_LISTEN_PORT

    if args.listen:
        ApiServer(s, args.listen, clients, known_devices)

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
    signal.signal(signal.SIGTERM, sigterm_handler)
    try:
        # say hello or probe network for other hosts
        for h in handlers:
            h.startup()

        while True:
            try:
                timeout = send_outstanding_messages()
                events = s.select(timeout)
                for key, mask in events:
                    if isinstance(key.data, MulticastInterface):
                        key.data.handle_request(key)
                    else:
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
    for h in handlers:
        h.teardown()

    send_outstanding_messages(True)
    logger.info('Done.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
