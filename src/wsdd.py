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
# (c) Steffen Christgau, 2017-2020

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


class MulticastHandler:
    """
    A class for handling multicast traffic on a given interface for a
    given address family. It provides multicast sender and receiver sockets
    """
    # TODO: this one needs some cleanup
    def __init__(self, family, address, interface, selector):
        self.address = address
        self.family = family
        self.interface = interface
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
            self.multicast_address, self.interface.name, self.address))
        logger.debug('transport address on {0} is {1}'.format(
            self.interface.name, self.transport_address))
        logger.debug('will listen for HTTP traffic on address {0}'.format(
            self.listen_address))

        self.selector.register(self.recv_socket, selectors.EVENT_READ, self)
        self.selector.register(self.send_socket, selectors.EVENT_READ, self)

    def cleanup(self):
        self.selector.unregister(self.recv_socket)
        self.selector.unregister(self.send_socket)

        self.recv_socket.close()
        self.send_socket.close()

    def handles(self, family, addr, interface):
        return (self.family == family and self.address == addr and
                self.interface.name == interface.name)

    def init_v6(self):
        idx = socket.if_nametoindex(self.interface.name)
        self.multicast_address = (WSD_MCAST_GRP_V6, WSD_UDP_PORT, 0x575C, idx)

        # v6: member_request = { multicast_addr, intf_idx }
        mreq = (
            socket.inet_pton(self.family, WSD_MCAST_GRP_V6) +
            struct.pack('@I', idx))
        self.recv_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        self.recv_socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        # Could anyone ask the Linux folks for the rationale for this!?
        if platform.system() == 'Linux':
            try:
                # supported starting from Linux 4.20
                IPV6_MULTICAST_ALL = 29
                self.recv_socket.setsockopt(
                    socket.IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)
            except OSError as e:
                logger.warning('cannot unset all_multicast: {}'.format(e))

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
        idx = socket.if_nametoindex(self.interface.name)
        self.multicast_address = (WSD_MCAST_GRP_V4, WSD_UDP_PORT)

        # v4: member_request (ip_mreqn) = { multicast_addr, intf_addr, idx }
        mreq = (
            socket.inet_pton(self.family, WSD_MCAST_GRP_V4) +
            socket.inet_pton(self.family, self.address) +
            struct.pack('@I', idx))
        self.recv_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        if platform.system() == 'Linux':
            IP_MULTICAST_ALL = 49
            self.recv_socket.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 0)

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

    def cleanup(self):
        pass

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

    def handle_message(self, msg, mch, src_address):
        """
        handle a WSD message that might be received by a MulticastHandler
        """
        tree = ElementTree.fromstring(msg)
        header = tree.find('./soap:Header', namespaces)
        msg_id_tag = header.find('./wsa:MessageID', namespaces)
        if msg_id_tag is None:
            return None

        msg_id = msg_id_tag.text

        # if message came over a MulticastHandler, check for duplicates
        if mch and self.is_duplicated_msg(msg_id):
            logger.debug('known message ({0}): dropping it'.format(msg_id))
            return None

        action_tag = header.find('./wsa:Action', namespaces)
        if action_tag is None:
            return None

        action = action_tag.text
        _, _, action_method = action.rpartition('/')

        if mch:
            logger.info('{}:{}({}) - - "{} {} UDP" - -'.format(
                src_address[0], src_address[1], mch.interface.name,
                action_method, msg_id
            ))
        else:
            # http logging is already done by according server
            logger.debug('processing WSD {} message ({})'.format(
                action_method, msg_id))

        body = tree.find('./soap:Body', namespaces)
        if body is None:
            return None

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
    """
    A message handler that handles traffic received via MutlicastHandler.
    """

    def __init__(self, mch):
        super().__init__()

        self.mch = mch

    def teardown(self):
        pass

    def enqueue_datagram(self, msg, address=None, msg_type=None):
        """
        Add an outgoing WSD (SOAP) message to the queue of outstanding messages

        Implements SOAP over UDP, Appendix I.
        """
        if not address:
            address = self.mch.multicast_address

        if msg_type:
            logger.debug('scheduling {0} message via {1} to {2}'.format(
                msg_type, self.mch.interface.name, address))

        msg_count = (
            MULTICAST_UDP_REPEAT
            if address == self.mch.multicast_address
            else UNICAST_UDP_REPEAT)

        due_time = time.time()
        t = random.randint(UDP_MIN_DELAY, UDP_MAX_DELAY)
        for i in range(msg_count):
            send_queue.append([due_time, self.mch, address, msg])
            due_time += t / 1000
            t = min(t * 2, UDP_UPPER_DELAY)


class WSDDiscoveredDevice(object):

    def __init__(self, xml_str, xaddr, interface):
        self.last_seen = None
        self.addresses = {}
        self.props = {}
        self.display_name = ''

        self.update(xml_str, xaddr, interface)

    def update(self, xml_str, xaddr, interface):
        tree = ElementTree.fromstring(xml_str)
        mds_path = 'soap:Body/wsx:Metadata/wsx:MetadataSection'
        sections = tree.findall(mds_path, namespaces)
        for section in sections:
            dialect = section.attrib['Dialect']
            if dialect == WSDP_URI + '/ThisDevice':
                self.extract_wsdp_props(section, dialect)
            elif dialect == WSDP_URI + '/ThisModel':
                self.extract_wsdp_props(section, dialect)
            elif dialect == WSDP_URI + '/Relationship':
                host_xpath = ('wsdp:Relationship[@Type="{}/host"]/wsdp:Host'
                              .format(WSDP_URI))
                host_sec = section.find(host_xpath, namespaces)
                if (host_sec):
                    self.extract_host_props(host_sec)
            else:
                logger.debug('unknown metadata dialect ({})'.format(dialect))

        url = urllib.parse.urlparse(xaddr)
        addr, _, _ = url.netloc.rpartition(':')
        if interface not in self.addresses:
            self.addresses[interface] = set([addr])
        else:
            self.addresses[interface].add(addr)

        self.last_seen = time.time()
        if ('DisplayName' in self.props) and ('BelongsTo' in self.props):
            self.display_name = self.props['DisplayName']
            logger.info('discovered {} in {} on {}%{}'.format(
                self.display_name, self.props['BelongsTo'], addr,
                interface.interface.name))
        elif 'FriendlyName' in self.props:
            self.display_name = self.props['FriendlyName']
            logger.info('discovered {} on {}%{}'.format(
                self.display_name, addr, interface.interface.name))

        logger.debug(str(self.props))

    def extract_wsdp_props(self, root, dialect):
        _, _, propsRoot = dialect.rpartition('/')
        # XPath support is limited, so filter by namespace on our own
        nodes = root.findall('./wsdp:{0}/*'.format(propsRoot), namespaces)
        ns_prefix = '{{{}}}'.format(WSDP_URI)
        prop_nodes = [n for n in nodes if n.tag.startswith(ns_prefix)]
        for node in prop_nodes:
            tag_name = node.tag[len(ns_prefix):]
            self.props[tag_name] = node.text

    def extract_host_props(self, root):
        types = root.findtext('wsdp:Types', '', namespaces)
        self.props['types'] = types.split(' ')
        if types != PUB_COMPUTER:
            return

        comp = root.findtext(PUB_COMPUTER, '', namespaces)
        self.props['DisplayName'], _, self.props['BelongsTo'] = (
            comp.partition('/'))


class WSDClient(WSDUDPMessageHandler):

    def __init__(self, mch, known_devices):
        super().__init__(mch)

        self.mch.add_handler(self.mch.send_socket, self)
        self.mch.add_handler(self.mch.recv_socket, self)

        self.probes = {}
        self.known_devices = known_devices

        self.handlers[WSD_HELLO] = self.handle_hello
        self.handlers[WSD_BYE] = self.handle_bye
        self.handlers[WSD_PROBE_MATCH] = self.handle_probe_match
        self.handlers[WSD_RESOLVE_MATCH] = self.handle_resolve_match

        # avoid packet storm when hosts come up by delaying initial probe
        time.sleep(random.randint(0, MAX_STARTUP_PROBE_DELAY))
        self.send_probe()

    def cleanup(self):
        self.mch.remove_handler(self.mch.send_socket, self)
        self.mch.remove_handler(self.mch.recv_socket, self)

    def send_probe(self):
        """WS-Discovery, Section 4.3, Probe message"""
        self.remove_outdated_probes()

        probe = ElementTree.Element('wsd:Probe')
        ElementTree.SubElement(probe, 'wsd:Types').text = WSD_TYPE_DEVICE

        xml, i = self.build_message_tree(WSA_DISCOVERY, WSD_PROBE, None, probe)
        self.enqueue_datagram(self.xml_to_buffer(xml), msg_type='Probe')
        self.probes[i] = time.time()

    def teardown(self):
        self.remove_outdated_probes()

    def handle_request(self, msg, address):
        self.handle_message(msg, self.mch, address)

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
            logger.debug('resolve match without endpoint/xaddr')
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
        if self.mch.family == socket.AF_INET6:
            host = '[{}]'.format(url.partition('[')[2].partition(']')[0])
            url = url.replace(']', '%{}]'.format(self.mch.interface.name))

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
            logger.warning('could not fetch metadata from: {} {}'.format(
                url, e))

    def build_getmetadata_message(self, endpoint):
        tree, _ = self.build_message_tree(endpoint, WSD_GET, None, None)
        return self.xml_to_buffer(tree)

    def handle_metadata(self, meta, endpoint, xaddr):
        device_uuid = str(uuid.UUID(endpoint))
        if device_uuid in self.known_devices:
            self.known_devices[device_uuid].update(meta, xaddr, self.mch)
        else:
            self.known_devices[device_uuid] = WSDDiscoveredDevice(
                    meta, xaddr, self.mch)

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

    def __init__(self, mch):
        super().__init__(mch)

        self.mch.add_handler(self.mch.recv_socket, self)

        self.handlers[WSD_PROBE] = self.handle_probe
        self.handlers[WSD_RESOLVE] = self.handle_resolve

        self.send_hello()

    def teardown(self):
        self.send_bye()

    def handle_request(self, msg, address):
        reply = self.handle_message(msg, self.mch, address)
        if reply:
            self.enqueue_datagram(reply, address=address)

    def send_hello(self):
        """WS-Discovery, Section 4.1, Hello message"""
        hello = ElementTree.Element('wsd:Hello')
        self.add_endpoint_reference(hello)
        # THINK: Microsoft does not send the transport address here due
        # to privacy reasons. Could make this optional.
        self.add_xaddr(hello, self.mch.transport_address)
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

    def handle_resolve(self, header, body):
        resolve = body.find('./wsd:Resolve', namespaces)
        addr = resolve.find('./wsa:EndpointReference/wsa:Address', namespaces)
        if addr is None:
            logger.debug('invalid resolve request: missing endpoint address')
            return None

        if not addr.text == args.uuid.urn:
            logger.debug(
                'invalid resolve request: address ({}) does not '
                'match own one ({})'.format(addr.text, args.uuid.urn))
            return None

        matches = ElementTree.Element('wsd:ResolveMatches')
        match = ElementTree.SubElement(matches, 'wsd:ResolveMatch')
        self.add_endpoint_reference(match)
        self.add_types(match)
        self.add_xaddr(match, self.mch.transport_address)
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

    def __init__(self, mch, RequestHandlerClass, addr_family, sel):
        # hacky way to convince HTTP/SocketServer of the address family
        type(self).address_family = addr_family

        # remember actual address family used by the server instance
        self.addr_family = addr_family
        self.mch = mch
        self.selector = sel
        self.wsd_handler = WSDHttpMessageHandler()
        self.registered = False

        super().__init__(mch.listen_address, RequestHandlerClass)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

        super().server_bind()

    def server_activate(self):
        super().server_activate()
        self.selector.register(self.fileno(), selectors.EVENT_READ, self)
        self.registered = True

    def server_close(self):
        if self.registered:
            self.selector.unregister(self.fileno())
        super().server_close()


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
                c.mch.interface.name == interface or not interface]

    def get_list_reply(self):
        retval = ''
        for dev_uuid in self.server.wsd_known_devices:
            dev = self.server.wsd_known_devices[dev_uuid]
            addrs_str = []
            for mci, addrs in dev.addresses.items():
                addrs_str.append(', '.join(['{}%{}'.format(
                    a, mci.interface.name) for a in addrs]))

            retval = retval + '{}\t{}\t{}\t{}\t{}\n'.format(
                dev_uuid,
                dev.display_name,
                dev.props['BelongsTo'] if 'BelongsTo' in dev.props else '',
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


class NetworkInterface(object):

    def __init__(self, name, scope):
        self.name = name
        self.scope = scope


class MetaEnumAfterInit(type):

    def __call__(cls, *args, **kwargs):
        obj = super().__call__(*args, **kwargs)
        obj.enumerate()
        return obj


class NetworkAddressMonitor(object,  metaclass=MetaEnumAfterInit):
    """
    Observes changes of network addresses, handles addition and removal of
    network addresses, and filters for addresses/interfaces that are or are not
    handled. The actual OS-specific implementation that detects the changes is
    done in subclasses.
    """

    def __init__(self, selector):
        self.interfaces = {}
        self.selector = selector

        self.clients = []
        self.hosts = []
        self.mchs = []
        self.http_servers = []
        self.known_devices = {}

    def enumerate(self):
        """
        Performs an initial enumeration of addresses and sets up everything
        for observing future changes.
        """
        pass

    def handle_request(self):
        """ handle network change message """
        pass

    def add_interface(self, name, idx, scope):
        if idx in self.interfaces:
            self.interfaces[idx].name = name
        else:
            self.interfaces[idx] = NetworkInterface(name, scope)

        return self.interfaces[idx]

    def is_address_handled(self, addr, addr_family, interface):
        """
        Check if we should handle that address.
        Address must be provided as raw address, i.e. byte array
        """
        if args.ipv4only and addr_family != socket.AF_INET:
            return False
        if args.ipv6only and addr_family != socket.AF_INET6:
            return False

        # Nah, this check is not optimal but there are no local flags for
        # addresses, but it should be safe for IPv4 anyways
        # (https://tools.ietf.org/html/rfc5735#page-3)
        if (addr_family == socket.AF_INET) and (addr[0] == 127):
            return False
        if (addr_family == socket.AF_INET6) and (addr[0:2] != b'\xfe\x80'):
            return False

        addr_str = socket.inet_ntop(addr_family, addr)

        if (args.interface) and (interface.name not in args.interface) and (
                addr_str not in args.interface):
            return False

        return True

    def handle_new_address(self, raw_addr, addr_family, interface):
        addr = socket.inet_ntop(addr_family, raw_addr)
        logger.debug('new address {} on {}'.format(addr, interface.name))

        if not self.is_address_handled(raw_addr, addr_family, interface):
            logger.debug('ignoring that address on {}'.format(interface.name))
            return

        # filter out what is not wanted
        # Ignore addresses or interfaces we already handle. There can only be
        # one multicast handler per address family and network interface
        # However, multiple link-local addresses can be
        for mch in self.mchs:
            if mch.handles(addr_family, addr, interface):
                return

        logger.debug('handling traffic for {} on {}'.format(
            addr, interface.name))
        mch = MulticastHandler(addr_family, addr, interface, self.selector)
        self.mchs.append(mch)

        if not args.no_host:
            h = WSDHost(mch)
            self.hosts.append(h)
            if not args.no_http:
                self.http_servers.append(WSDHttpServer(
                    mch, WSDHttpRequestHandler, mch.family, self.selector))

        if args.discovery:
            client = WSDClient(mch, self.known_devices)
            self.clients.append(client)

    def handle_deleted_address(self, raw_addr, addr_family, interface):
        addr = socket.inet_ntop(addr_family, raw_addr)
        logger.info('deleted address {} on {}'.format(addr, interface.name))

        if not self.is_address_handled(raw_addr, addr_family, interface):
            return

        mch = self.get_mch_by_address(addr_family, addr, interface)
        if mch is None:
            return

        # Do not tear the client/hosts down. Saying goodbye does not work
        # because the address is already gone (at least on Linux).
        for c in self.clients:
            if c.mch == mch:
                c.cleanup()
                self.clients.remove(c)
                break
        for h in self.hosts:
            if h.mch == mch:
                h.cleanup()
                self.hosts.remove(h)
                break
        for s in self.http_servers:
            if s.mch == mch:
                s.server_close()
                self.http_servers.remove(s)

        mch.cleanup()
        self.mchs.remove(mch)

    def cleanup(self):

        for h in self.hosts:
            h.teardown()
            h.cleanup()

        for c in self.clients:
            c.teardown()
            c.cleanup()

    def get_mch_by_address(self, family, address, interface):
        """
        Get the MCI for the address, its family and the interface.
        adress must be given as a string.
        """
        for retval in self.mchs:
            if retval.handles(family, address, interface):
                return retval

        return None


# from rtnetlink.h
RTMGRP_LINK = 1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV6_IFADDR = 0x100

# from netlink.h
NLM_HDR_LEN = 16

NLM_F_REQUEST = 0x01
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

# self defines
NLM_HDR_LEN = 16
NLM_HDR_ALIGNTO = 4

# ifa flags
IFA_F_DADFAILED = 0x08
IFA_F_HOMEADDRESS = 0x10
IFA_F_DEPRECATED = 0x20
IFA_F_TENTATIVE = 0x40

# from if_addr.h
IFA_ADDRESS = 1
IFA_LOCAL = 2
IFA_LABEL = 3
IFA_FLAGS = 8
IFA_MSG_LEN = 8

RTA_ALIGNTO = 4
RTA_LEN = 4


class NetlinkAddressMonitor(NetworkAddressMonitor):
    """
    Implementation of the AddressMonitor for Netlink sockets, i.e. Linux
    """

    RTM_NEWADDR = 20
    RTM_DELADDR = 21
    RTM_GETADDR = 22

    def __init__(self, selector):
        super().__init__(selector)

        rtm_groups = RTMGRP_LINK
        if not args.ipv4only:
            rtm_groups = rtm_groups | RTMGRP_IPV6_IFADDR
        if not args.ipv6only:
            rtm_groups = rtm_groups | RTMGRP_IPV4_IFADDR

        self.socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                                    socket.NETLINK_ROUTE)
        self.socket.bind((0, rtm_groups))
        self.selector.register(self.socket, selectors.EVENT_READ, self)

    def enumerate(self):
        super().enumerate()

        kernel = (0, 0)
        req = struct.pack('@IHHIIB', NLM_HDR_LEN + 1, self.RTM_GETADDR,
                          NLM_F_REQUEST | NLM_F_DUMP, 1, 0, socket.AF_PACKET)
        self.socket.sendto(req, kernel)

    def handle_request(self):
        super().handle_request()

        buf, src = self.socket.recvfrom(4096)
        logger.debug('netlink message with {} bytes'.format(len(buf)))

        offset = 0
        while offset < len(buf):
            h_len, h_type, _, _, _ = struct.unpack_from('@IHHII', buf, offset)
            offset += NLM_HDR_LEN

            msg_len = h_len - NLM_HDR_LEN
            if msg_len < 0:
                break

            if h_type != self.RTM_NEWADDR and h_type != self.RTM_DELADDR:
                logger.debug('invalid rtm_message type {}'.format(h_type))
                offset += ((msg_len + 1) // NLM_HDR_ALIGNTO) * NLM_HDR_ALIGNTO
                continue

            # decode ifaddrmsg as in rtnetlink.h
            ifa_family, _, ifa_flags, ifa_scope, ifa_idx = struct.unpack_from(
                '@BBBBI', buf, offset)
            if (ifa_flags & IFA_F_DADFAILED or ifa_flags & IFA_F_HOMEADDRESS or
               ifa_flags & IFA_F_DEPRECATED or ifa_flags & IFA_F_TENTATIVE):
                logger.debug('ignore address with invalid state {}'.format(
                    hex(ifa_flags)))
                offset += ((msg_len + 1) // NLM_HDR_ALIGNTO) * NLM_HDR_ALIGNTO
                continue

            addr = None
            i = offset + IFA_MSG_LEN
            while i - offset < msg_len:
                attr_len, attr_type = struct.unpack_from('HH', buf, i)

                if attr_len < RTA_LEN:
                    break

                if attr_type == IFA_LABEL:
                    name, = struct.unpack_from(str(attr_len - 4 - 1) + 's',
                                               buf, i + 4)
                    self.add_interface(name.decode(), ifa_idx, ifa_scope)
                elif attr_type == IFA_LOCAL and ifa_family == socket.AF_INET:
                    addr = buf[i + 4:i + 4 + 4]
                elif (attr_type == IFA_ADDRESS and
                        ifa_family == socket.AF_INET6):
                    addr = buf[i + 4:i + 4 + 16]
                elif attr_type == IFA_FLAGS:
                    _, ifa_flags = struct.unpack_from('HI', buf, i)
                i += ((attr_len + 1) // RTA_ALIGNTO) * RTA_ALIGNTO
                logger.debug('rt_attr {} {}'.format(attr_len, attr_type))

            if addr is None:
                logger.debug('not address in RTM message')
                offset += ((msg_len + 1) // NLM_HDR_ALIGNTO) * NLM_HDR_ALIGNTO
                continue

            if ifa_idx in self.interfaces:
                iface = self.interfaces[ifa_idx]
                if h_type == self.RTM_NEWADDR:
                    self.handle_new_address(addr, ifa_family, iface)
                elif h_type == self.RTM_DELADDR:
                    self.handle_deleted_address(addr, ifa_family, iface)
            else:
                logger.debug('unknown interface index: {}'.format(ifa_idx))

            offset += ((msg_len + 1) // NLM_HDR_ALIGNTO) * NLM_HDR_ALIGNTO

    def cleanup(self):
        self.selector.unregister(self.socket)
        self.socket.close()
        super().cleanup()


# from sys/net/route.h
RTA_IFA = 0x20

# from sys/socket.h
CTL_NET = 4
NET_RT_IFLIST = 3

# from sys/net/if.h
IFF_LOOPBACK = 0x8
IFF_MULTICAST = 0x800

# sys/netinet6/in6_var.h
IN6_IFF_TENTATIVE = 0x02
IN6_IFF_DUPLICATED = 0x04
IN6_IFF_NOTREADY = IN6_IFF_TENTATIVE | IN6_IFF_DUPLICATED

SA_ALIGNTO = ctypes.sizeof(ctypes.c_long)


class RouteSocketAddressMonitor(NetworkAddressMonitor):
    """
    Implementation of the AddressMonitor for FreeBSD using route sockets
    """

    # from sys/net/route.h
    RTM_NEWADDR = 0xC
    RTM_DELADDR = 0xD
    RTM_IFINFO = 0xE

    def __init__(self, selector):
        super().__init__(selector)
        self.intf_blacklist = []

        # Create routing socket to get notified about future changes.
        # Do this before fetching the current routing information to avoid
        # race condition.
        self.socket = socket.socket(socket.AF_ROUTE, socket.SOCK_RAW,
                                    socket.AF_UNSPEC)
        self.selector.register(self.socket, selectors.EVENT_READ, self)

    def enumerate(self):
        super().enumerate()
        mib = [CTL_NET, socket.AF_ROUTE, 0, 0, NET_RT_IFLIST, 0]
        rt_mib = (ctypes.c_int * len(mib))()
        rt_mib[:] = mib[:]

        libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

        # Ask kernel for routing table size first.
        rt_size = ctypes.c_size_t()
        if libc.sysctl(ctypes.byref(rt_mib), ctypes.c_size_t(len(rt_mib)), 0,
                       ctypes.byref(rt_size), 0, 0):
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

        # Get the initial routing (interface list) data.
        rt_buf = ctypes.create_string_buffer(rt_size.value)
        if libc.sysctl(ctypes.byref(rt_mib), ctypes.c_size_t(len(rt_mib)),
                       rt_buf, ctypes.byref(rt_size), 0, 0):
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

        self.parse_route_socket_response(rt_buf.raw, True)

    def handle_request(self):
        super().handle_request()

        self.parse_route_socket_response(self.socket.recv(4096), False)

    def parse_route_socket_response(self, buf, keep_intf):
        offset = 0

        intf = None
        intf_flags = 0
        while offset < len(buf):
            rtm_len, _, rtm_type = struct.unpack_from('@HBB', buf, offset)
            # addr_mask has same offset in if_msghdr and ifs_msghdr
            addr_mask, flags = struct.unpack_from('ii', buf, offset + 4)

            msg_types = [self.RTM_NEWADDR, self.RTM_DELADDR, self.RTM_IFINFO]
            if rtm_type not in msg_types:
                offset += rtm_len
                continue

            if rtm_type == self.RTM_IFINFO:
                intf_flags = flags

            # those offset may unfortunately be architecture dependent
            sa_offset = offset + ((16 + 152) if rtm_type == self.RTM_IFINFO
                                  else 20)

            # For a route socket message, and different to a sysctl response,
            # the link info is stored inside the same rtm message, so it has to
            # survive multiple rtm messages in such cases
            if not keep_intf:
                intf = None

            new_intf = self.parse_addrs(buf, sa_offset, offset + rtm_len,
                                        intf, addr_mask, rtm_type, intf_flags)
            intf = new_intf if new_intf else intf

            offset += rtm_len

    def parse_addrs(self, buf, offset, limit, intf, addr_mask, rtm_type,
                    flags):
        addr_type_idx = 1
        addr = None
        addr_family = None
        while offset < limit:
            while (not (addr_type_idx & addr_mask) and
                    (addr_type_idx <= addr_mask)):
                addr_type_idx = addr_type_idx << 1

            sa_len, sa_fam = struct.unpack_from('@BB', buf, offset)
            if (sa_fam in [socket.AF_INET, socket.AF_INET6] and
                    addr_type_idx == RTA_IFA):
                addr_family = sa_fam
                addr_offset = 4 if sa_fam == socket.AF_INET else 8
                addr_length = 16 if sa_fam == socket.AF_INET6 else 4
                addr_start = offset + addr_offset
                addr = buf[addr_start:addr_start + addr_length]
            elif sa_fam == socket.AF_LINK:
                idx, _, name_len = struct.unpack_from('@HBB', buf, offset + 2)
                if idx > 0:
                    off_name = offset + 8
                    if_name = (buf[off_name:off_name + name_len]).decode()
                    intf = self.add_interface(if_name, idx, idx)

            offset += (((sa_len + SA_ALIGNTO - 1) // SA_ALIGNTO) * SA_ALIGNTO
                       if sa_len > 0 else SA_ALIGNTO)
            addr_type_idx = addr_type_idx << 1

        if rtm_type == self.RTM_IFINFO and intf is not None:
            if flags & IFF_LOOPBACK or not flags & IFF_MULTICAST:
                self.intf_blacklist.append(intf.name)
            elif intf in self.intf_blacklist:
                self.intf_blacklist.remove(intf.name)

        if intf is None or intf.name in self.intf_blacklist or addr is None:
            return intf

        if rtm_type == self.RTM_DELADDR:
            self.handle_deleted_address(addr, addr_family, intf)
        else:
            # Too bad, the address may be unuseable (tentative, e.g.) here
            # but we won't get any further notifcation about the address being
            # available for use. Thus, we try and may fail here
            self.handle_new_address(addr, addr_family, intf)

        return intf

    def cleanup(self):
        self.selector.unregister(self.socket)
        self.socket.close()
        super().cleanup()


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
        mch = send_queue[-1][1]
        addr = send_queue[-1][2]
        msg = send_queue[-1][3]
        try:
            mch.send_socket.sendto(msg, addr)
        except Exception as e:
            logger.error('error while sending packet on {}: {}'.format(
                mch.interface.name, e))

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
    parse_args()

    if not args.discovery and args.listen:
        logger.warning('Listen option ignored since discovery is disabled.')
    elif args.discovery and not args.listen:
        logger.warning('Discovery enabled but no listen option provided. '
                       'Falling back to port {}'.format(WSDD_LISTEN_PORT))
        args.listen = WSDD_LISTEN_PORT

    if args.ipv4only and args.ipv6only:
        logger.error('Listening to no IP address family.')
        return 4

    s = selectors.DefaultSelector()
    if platform.system() == 'Linux':
        nm = NetlinkAddressMonitor(s)
    elif platform.system() == 'FreeBSD':
        nm = RouteSocketAddressMonitor(s)
    else:
        raise NotImplementedError('unsupported OS')

    if args.listen:
        ApiServer(s, args.listen, nm.clients, nm.known_devices)

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
        while True:
            try:
                timeout = send_outstanding_messages()
                events = s.select(timeout)
                for key, mask in events:
                    if isinstance(key.data, MulticastHandler):
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

    nm.cleanup()

    send_outstanding_messages(True)
    logger.info('Done.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
