#!/usr/bin/python

"""
This module provides an implementation of a STAMP Session Sender defined in
RFC 8762.
"""

from concurrent import futures
from threading import Thread, Event
import argparse
import logging
import netifaces
import os
import socket
import struct
import time
import typing
import select

import grpc

import sys
# from pkg_resources import resource_filename
# sys.path.append(resource_filename(__name__, 'commons/protos/srv6pm/gen_py/'))

# sys.path.append("./")

# import common_pb2
# import stamp_sender_pb2
# import stamp_sender_pb2_grpc

from .ProbingAgentExceptions import (
    InternalError,
    InvalidArgumentError,
    NodeInitializedError,
    NodeNotInitializedError,
    ResetSTAMPNodeError,
    STAMPSessionExistsError,
    STAMPSessionNotFoundError,
    STAMPSessionNotRunningError,
    STAMPSessionRunningError,
    SSIDOutOfRangeError
)

from scapy.supersocket import L3RawSocket
from scapy.sendrecv import AsyncSniffer
from scapy.layers.inet import IP, Ether, UDP

from .utils_ipv4 import (
    MAX_SEQUENCE_NUMBER,
    MAX_SSID,
    MIN_SSID,
    NEXT_HEADER_IPV6_FIELD,
    NEXT_HEADER_SRH_FIELD,
    ROUTING_HEADER_PROTOCOL_NUMBER,
    UDP_DEST_PORT_FIELD,
    UDP_PROTOCOL_NUMBER,
    SRH_OFFSET,
    HDR_EXT_LEN_SRH_OFFSET,
    IPV4_PROTOCOL_OFFSET,
    STAMPSenderSession,
    # grpc_to_py_resolve_defaults,
    # py_to_grpc
)

from . import stamp
from .stamp import (
    AuthenticationMode,
    TimestampFormat,
    PacketLossType,
    DelayMeasurementMode
)

from .sniffer import AsyncSniffer as AsyncSnifferRaw


# Default command-line arguments
DEFAULT_GRPC_IP = None
DEFAULT_GRPC_PORT = 12345

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
    datefmt='%m-%d %H:%M')

# Get the root logger
logger = logging.getLogger()

RAW_PROCESSING = False


class STAMPSessionSender:
    """
    Provides methods that implement the functionalities of a STAMP Session
    Sender.
    """

    def __init__(self, stop_event=None):
        # Initialize super class STAMPSessionSenderService
        super().__init__()
        # Interfaces on which the Sender listens for STAMP packets
        self.stamp_interfaces = None
        # IP address to be used as source IPv4 address of the STAMP Test
        # packets. This parameter can be overridden by setting the
        # stamp_source_ipv4_address attribute in the STAMPSession
        # If it is None, the loopback IPv4 address will be used.
        self.stamp_source_ipv4_address = None
        # Socket used to send and receive STAMP packets
        self.sender_socket = None
        # Thread to receive the incoming STAMP Test Reply packets
        self.stamp_packet_receiver = None
        # Is sender initialized?
        self.is_initialized = False
        # A dict containing informations about the running STAMP Sessions
        self.stamp_sessions = dict()
        # Sender sockets, place holder for the port number to prevent other 
        # applications from using the STAMP port
        self.sender_sockets = dict()
        # Thread to send test packets
        # TODO: Those threads shoud be matined in the STAMPSession object
        self.sending_thread = dict()
        # Reflector port number
        # TODO: tempory solution 
        self.reflector_port = None
        
        # Stop event. If set, something has requested the termination of
        # the device and we need to gracefully shutdown this script
        # self.stop_event = stop_event
        # Start a thread to listen for stop events
        # if stop_event is not None:
        #     Thread(target=self.shutdown_sender).start()

    def shutdown_sender(self):
        # # Wait until a termination signal is received
        # self.stop_event.wait()
        # Received termination signal
        logging.info(
            'Received shutdown command. Gracefully terminating sender.'
        )
        self.reset()

    def is_session_valid(self, ssid):
        """
        Check if a STAMP Session is valid.

        Parameters
        ----------
        ssid : int
            SSID of the STAMP Session to check.

        Returns
        -------
        is_session_valid : bool
            True if the STAMP Session is valid, False otherwise.
        """

        return ssid in self.stamp_sessions

    def is_session_running(self, ssid):
        """
        Check if a STAMP Session is running.

        Parameters
        ----------
        ssid : int
            SSID of the STAMP Session to check.

        Returns
        -------
        is_session_valid : bool
            True if the STAMP Session is running, False otherwise.
        """

        return self.stamp_sessions[ssid].is_running

    def stamp_reply_packet_received(self, raw_packet):
        """
        Called when a STAMP Test Reply packet is received: validate the
         received packet, extract the timestamps and add the timestamp to the
         results queue of the STAMP Session.

        Parameters
        ----------
        packet : scapy.packet.Packet
            The STAMP Test Reply packet received from the Reflector.

        Returns
        -------
        None.
        """

        logger.debug('STAMP Test Reply packet received: %s',
                      raw_packet.show(dump=True)) 
        
        raw_packet = bytes(raw_packet[Ether][IP][UDP].payload)

        # Parse the received STAMP Test Reply packet
        stamp_reply_packet = stamp.parse_stamp_reply_packet(stamp.STAMPReplyPacket(raw_packet))

        # Get the STAMP Session by SSID
        stamp_session = self.stamp_sessions.get(stamp_reply_packet.ssid, None)

        # Validate the STAMP packet and drop the packet if it is not valid

        logger.debug('Validating STAMP Session, SSID: %d',
                     stamp_reply_packet.ssid)

        # Drop STAMP packet if SSID does not correspond to any STAMP Session
        if stamp_session is None:
            logging.error('Received an invalid STAMP Test Reply packet: '
                          'Session with SSID %d does not exists',
                          stamp_reply_packet.ssid)
            return  # Drop the packet

        # Drop STAMP packet if the Session is not running
        if not stamp_session.is_running:
            logging.error('Received an invalid STAMP Test Reply packet: '
                          'Session with SSID %d is not running',
                          stamp_reply_packet.ssid)
            return  # Drop the packet

        # Take the STAMP Test Reply packet receive timestamp
        timestamp = stamp.get_timestamp_unix()

        # Append the timestamps to the results queue of the current STAMP
        # Session
        stamp_session.add_test_results(
            test_pkt_tx_timestamp=stamp_reply_packet.sender_timestamp,
            reply_pkt_tx_timestamp=stamp_reply_packet.timestamp,
            reply_pkt_rx_timestamp=timestamp,
            test_pkt_rx_timestamp=stamp_reply_packet.receive_timestamp
        )

        logger.debug(
            'New measure collected for Session %d: '
            'test_pkt_tx_timestamp=%f, '
            'reply_pkt_tx_timestamp=%f, '
            'reply_pkt_rx_timestamp=%f, '
            'test_pkt_rx_timestamp=%f',
            stamp_reply_packet.ssid,
            stamp_reply_packet.sender_timestamp,
            stamp_reply_packet.timestamp,
            timestamp,
            stamp_reply_packet.receive_timestamp
        )

    def stamp_reply_packet_received_raw(self, packet, ts):
        """
        Called when a STAMP Test packet is received: validate the received
         packet, generate a STAMP Test Reply packet and send it to the
         Session-Sender.
        Parameters
        ----------
        packet : scapy.packet.Packet
            The STAMP Test packet received from the Sender.
        Returns
        -------
        None.
        """

        #logger.debug('STAMP Test packet received: \n\n%s',
        #             packet.show(dump=True))

        ethernet_length = 14  # Length of the Ethernet header

        udp_length = 8

        ip_length = packet[IP].ihl

        # srh_length = 8 + 8*packet[ethernet_length + SRH_OFFSET + HDR_EXT_LEN_SRH_OFFSET]
        stamp_offset = ethernet_length + ip_length + udp_length

        #stamp_reply_payload_offset = ipv6_offset + 8 + len(stamp_session.return_sidlist)

        ssid = struct.unpack('!H', packet[stamp_offset + stamp.core.SSID_OFFSET : stamp_offset + stamp.core.SSID_OFFSET + stamp.core.SSID_LENGTH])[0]

        # Get the STAMP Session by SSID
        stamp_session = self.stamp_sessions.get(ssid, None)

        # Validate the STAMP packet and drop the packet if it is not valid

        logger.debug('Validating STAMP Session, SSID: %d', ssid)

        # Drop STAMP packet if SSID does not correspond to any STAMP Session
        if stamp_session is None:
            logger.error('Received an invalid STAMP Test packet: '
                         'Session with SSID %d does not exists',
                         ssid)
            return  # Drop the packet

        # Drop STAMP packet if the Session is not running
        if not stamp_session.is_running:
            logger.error('Received an invalid STAMP Test packet: '
                         'Session with SSID %d is not running',
                         ssid)
            return  # Drop the packet

        t3 = struct.unpack('!2I', packet[stamp_offset + stamp.core.TIMESTAMP_OFFSET : stamp_offset + stamp.core.TIMESTAMP_OFFSET + stamp.core.TIMESTAMP_LENGTH])[0]
        t2 = struct.unpack('!2I', packet[stamp_offset + stamp.core.RECEIVE_TIMESTAMP_OFFSET : stamp_offset + stamp.core.RECEIVE_TIMESTAMP_OFFSET + stamp.core.RECEIVE_TIMESTAMP_LENGTH])[0]
        t1 = struct.unpack('!2I', packet[stamp_offset + stamp.core.SENDER_INFORMATION_OFFSET + stamp.core.SEQUENCE_NUMBER_LENGTH : stamp_offset + stamp.core.SENDER_INFORMATION_OFFSET + stamp.core.SEQUENCE_NUMBER_LENGTH + stamp.core.RECEIVE_TIMESTAMP_LENGTH])[0]

        # Take the STAMP Test Reply packet receive timestamp
        t4 = stamp.get_timestamp_unix()

        # Append the timestamps to the results queue of the current STAMP
        # Session
        stamp_session.add_test_results(
            test_pkt_tx_timestamp=t1,
            reply_pkt_tx_timestamp=t3,
            reply_pkt_rx_timestamp=t4,
            test_pkt_rx_timestamp=t2
        )

        # Sequence number depends on the Session Reflector Mode
        #if stamp_session.stamp_params.session_reflector_mode == \
        #        SessionReflectorMode.SESSION_REFLECTOR_MODE_STATELESS.value:
        #    # As explained in RFC 8762, in stateless mode:
        #    #    The STAMP Session-Reflector does not maintain test state and
        #    #    will use the value in the Sequence Number field in the
        #    #    received packet as the value for the Sequence Number field in
        #    #    the reflected packet.
        #    pass
        #elif stamp_session.stamp_params.session_reflector_mode == \
        #        SessionReflectorMode.SESSION_REFLECTOR_MODE_STATEFUL.value:
        #    # As explained in RFC 8762, in stateful mode:
        #    #    STAMP Session-Reflector maintains the test state, thus
        #    #    allowing the Session-Sender to determine directionality of
        #    #    loss using the combination of gaps recognized in the Session
        #    #    Sender Sequence Number and Sequence Number fields,
        #    #    respectively.
        #    raise NotImplementedError  # Currently we don't support it

        #stamp_reply_payload_offset = ipv6_offset + 40 + 8 + 16 * len(stamp_session.return_sidlist) + 8 - 14

        # If the packet is valid, generate the STAMP Test Reply packet
        #reply_packet = libstamp.core.generate_stamp_test_reply_packet_from_template(
        #    template_packet=stamp_session.packet_template,
        #    pseudo_hdr=stamp_session.pseudo_header,
        #    stamp_test_packet=packet,
        #    stamp_test_payload_offset=stamp_offset,
        #    stamp_reply_payload_offset=stamp_reply_payload_offset,
        #    #dst_ip=None,  # retrieved fromt the sidlist
        #    #dst_udp_port=stamp_test_packet.src_udp_port,
        #    sequence_number=None,
        #    timestamp_format=stamp_session.timestamp_format,
        #)

        # Send the reply packet to the Sender
        #print('dst', stamp_session.return_sidlist[0])
        #libstamp.core.send_stamp_packet_raw(reply_packet, stamp_session.return_sidlist[0], self.reflector_socket.outs)

    def build_stamp_reply_packets_sniffer(self):
        """
        Return a STAMP packets sniffer.

        Returns
        -------
        sniffer : scapy.sendrecv.AsyncSniffer
            Return an AsyncSniffer.
        """

        # Build a BPF filter expression to filter STAMP packets received
        # stamp_filter = (
        #     '{next_header_ipv6_field} == {routing_header_protocol_number} && '
        #     '{next_header_srh_field} == {udp_protocol_number} && '
        #     '{udp_dest_port_field} == {stamp_port}'.format(
        #         next_header_ipv6_field=NEXT_HEADER_IPV6_FIELD,
        #         routing_header_protocol_number=ROUTING_HEADER_PROTOCOL_NUMBER,
        #         next_header_srh_field=NEXT_HEADER_SRH_FIELD,
        #         udp_protocol_number=UDP_PROTOCOL_NUMBER,
        #         udp_dest_port_field=UDP_DEST_PORT_FIELD,
        #         stamp_port=self.sender_udp_port)
        # )
        stamp_filter = (
            "dst host {dst_ip} and "
            "udp src port {src_port}".format(
                dst_ip=self.stamp_source_ipv4_address,
                src_port=self.reflector_port,
                )
        )

        logging.debug('Creating AsyncSniffer, iface: {iface}, '
                      'filter: {filter}'.format(
                          iface=self.stamp_interfaces, filter=stamp_filter))

        # Create and return an AsyncSniffer
        if RAW_PROCESSING:
            sniffer = AsyncSnifferRaw(
                iface=self.stamp_interfaces[0],
                filter=stamp_filter,
                prn=self.stamp_reply_packet_received_raw)
        else:
            sniffer = AsyncSniffer(
                iface=self.stamp_interfaces,
                filter=stamp_filter,
                store=False,
                prn=self.stamp_reply_packet_received)
        return sniffer

    def send_stamp_packet_periodic(self, ssid, interval=10):
        """
        Send a STAMP packet periodically (with increasings sequence numbers).
         Sending is stopped when the threading event stop_flag of this class
         is set.

        Parameters
        ----------
        ssid : int
            16-bit STAMP Session Identifier (SSID).
        interval : int, optional
            Time (in seconds) between two STAMP packets (default 10).

        Returns
        -------
        None
        """

        # Get STAMP Session parameters
        stamp_session = self.stamp_sessions[ssid]
        sender_udp_port = self.stamp_sessions[ssid].sender_send_port
        stop_flag = stamp_session.stop_flag

        # Get an IPv6 address to be used as source IPv6 address for the STAMP
        # packet.
        #
        # We support three methods (listed in order of preference):
        #    * stamp_source_ipv6_address specific for this STAMP Session
        #    * global stamp_source_ipv6_address
        #    * IPv6 address of the loopback interface
        #
        # We use the specific stamp_source_ipv6_address; if it is None, we use
        # the global stamp_source_ipv6_address; if it is None, we use the IPv6
        # address of the loopback interface
        logger.debug('Getting a valid STAMP Source IPv4 Address')
        if stamp_session.sender_ipv4_addr is not None:
            ipv4_addr = stamp_session.sender_ipv4_addr
            logger.debug('Using the STAMP Session specific IPv4 '
                         'address: {ipv4_addr}'.format(ipv4_addr=ipv4_addr))
        elif self.stamp_source_ipv4_address is not None:
            ipv4_addr = self.stamp_source_ipv4_address
            logger.debug('Using the STAMP Session global IPv6 '
                         'address: {ipv4_addr}'.format(ipv4_addr=ipv4_addr))
        else:
            loopback_iface = netifaces.ifaddresses('lo')
            ipv4_addr = loopback_iface[netifaces.AF_INET][0]['addr']
            logger.debug('Using the loopback IPv4 address: {ipv4_addr}'
                         .format(ipv4_addr=ipv4_addr))

        # Start sending loop
        while not stop_flag.is_set():
            # Increase the Sequence Number
            stamp_session.sequence_number = \
                (stamp_session.sequence_number + 1) % (MAX_SEQUENCE_NUMBER + 1)

            # Create the packet
            packet = stamp.generate_stamp_test_packet(
                src_ip=ipv4_addr, dst_ip=stamp_session.reflector_ipv4_addr,
                src_udp_port=sender_udp_port,
                dst_udp_port=stamp_session.reflector_recv_port,
                ssid=stamp_session.ssid,
                sequence_number=stamp_session.sequence_number,
                timestamp_format=stamp_session.timestamp_format,
                ext_source_sync=False, scale=0, multiplier=1
            )

            # Send the STAMP Test packet
            stamp.send_stamp_packet(packet, self.sender_socket)

            # Wait before sending the next packet
            time.sleep(interval)

    def init(self, reflector_udp_port: int, interfaces: typing.List[str]=None,
             stamp_source_ipv4_address: str=None):
        """
        Initialize the STAMP Session Sender and prepare it to run STAMP
        Sessions.

        Parameters
        ----------
        sender_udp_port : int
            The UDP port to use for sending and receiving STAMP packets.
        interfaces : list, optional
            The list of interfaces on which the Sender will listen for
            STAMP packets. If the parameter is None, STAMP will listen on all
            the interfaces except the loopback interface (default: None).
        stamp_source_ipv6_address : str, optional
            The IPv6 address to be used as source address of the STAMP
            packets. If the parameter is None, STAMP will use the session
            specific IP, if provided, otherwise the loopback IP address will
            be used (default: None).

        Returns
        -------
        None.

        Raises
        ------
        NodeInitializedError
            If the STAMP Reflector is already initialized.
        InvalidArgumentError
            If an invalid UDP port number has been provided.
        InternalError
            If the Reflector failed to create a UDP socket.
        """

        logger.info('Initializing STAMP Session-Sender')

        # If already initialized, return an error
        if self.is_initialized:
            logging.error('Sender node has been already initialized')
            raise NodeInitializedError
        
        self.reflector_port = reflector_udp_port

        # Validate the UDP port provided
        # We also accept 0 as UDP port (port 0 means random port)
        # logger.debug('Validating the provided UDP port: %d',
        #              sender_udp_port)
        # if sender_udp_port not in range(0, 65536):
        #     logging.error('Invalid UDP port %d', sender_udp_port)
        #     raise InvalidArgumentError(type='udp_port',
        #                                value=str(sender_udp_port))
        # logger.info('UDP port %d is valid', sender_udp_port)

        # Extract the interface from the gRPC message
        # Interface is an optional argument; when omitted, we listen on all the
        # interfaces except loopback interface
        if interfaces is None or len(interfaces) == 0:
            # Get all the interfaces
            self.stamp_interfaces = netifaces.interfaces()
            # We exclude the loopback interface to avoid problems
            # From the scapy documentation...
            #    The loopback interface is a very special interface. Packets
            #    going through it are not really assembled and disassembled.
            #    The kernel routes the packet to its destination while it is
            #    still stored an internal structure
            self.stamp_interfaces.remove('lo')
        else:
            # One or more interfaces provided in the gRPC message
            self.stamp_interfaces = list(interfaces)

        # Extract STAMP Source IPv6 address from the request message
        # This parameter is optional, therefore we leave it to None if it is
        # not provided
        if stamp_source_ipv4_address:
            self.stamp_source_ipv4_address = stamp_source_ipv4_address

        # Open a Scapy socket (L3RawSocket6) for sending and receiving STAMP
        # packets; under the hood, L3RawSocket6 uses a AF_INET6 socket
        logger.debug('Creating a new sender socket')
        self.sender_socket = L3RawSocket()

        # Open a UDP socket
        # UDP socket will not be used at all, but we need for two reasons:
        # - to reserve STAMP UDP port and prevent other applications from
        #   using it
        # - to implement a mechanism of randomly chosen UDP port; indeed, to
        #   get a random free UDP port we can bind a UDP socket to port 0
        #   (only on the STAMP Sender)
        # logger.debug('Creating an auxiliary UDP socket')
        # self.auxiliary_socket = socket.socket(
        #     socket.AF_INET, socket.SOCK_DGRAM, 0)
        # try:
        #     self.auxiliary_socket.bind(('', sender_udp_port))
        # except OSError as err:
        #     logging.error('Cannot create UDP socket: %s', err)
        #     # Reset the node
        #     self.reset()
        #     # Return an error to the Controller
        #     raise InternalError(msg=err)
        # logger.info('Socket configured')

        # Extract the UDP port (this also works if we are chosing the port
        # randomly)
        # logger.debug('Configuring UDP port %d',
        #              self.auxiliary_socket.getsockname()[1])
        # self.sender_udp_port = self.auxiliary_socket.getsockname()[1]
        # logger.info('Using UDP port %d', self.sender_udp_port)

        #TODO
        # Set an iptables rule to drop STAMP packets after delivering them
        # to Scapy; this is required to avoid ICMP error messages when the
        # STAMP packets are delivered to a non-existing UDP port
        # rule_exists = os.system('ip6tables -t raw -C PREROUTING -p udp '
        #                         '--dport {port} -j DROP >/dev/null 2>&1'
        #                         .format(port=self.sender_udp_port)) == 0
        # if not rule_exists:
        #     logger.info('Setting ip6tables rule for STAMP packets')
        #     os.system('ip6tables -t raw -I PREROUTING -p udp --dport {port} '
        #               '-j DROP'.format(port=self.sender_udp_port))
        # else:
        #     logger.info('ip6tables rule for STAMP packets already exist. '
        #                 'Skipping')

        # Create and start a new thread to listen for incoming STAMP Test
        # Reply packets
        
        logger.info('Start sniffing...')
        self.stamp_packet_receiver = self.build_stamp_reply_packets_sniffer()
        logger.debug('Starting receive thread')
        self.stamp_packet_receiver.start()

        # Set "is_initialized" flag
        self.is_initialized = True

        # Success
        logger.debug('Initialization completed')

    def reset(self):
        """
        Helper function used to reset and stop the Sender. In order to reset a
        STAMP Sender there must be no STAMP sessions.

        Returns
        -------
        None.

        Raises
        ------
        ResetSTAMPNodeError
            If STAMP Sessions exist.
        """

        logger.info('Resetting STAMP Session-Sender')

        # Prevent reset if some sessions exist
        if len(self.stamp_sessions) != 0:
            logging.error('Reset failed: STAMP Sessions exist')
            raise ResetSTAMPNodeError('Reset failed: STAMP Sessions exist')

        # Stop and destroy the receive thread
        if self.stamp_packet_receiver is not None:
            logger.info('Stopping sniffer')
            self.stamp_packet_receiver.stop()
            # logger.info('Destroying receive thread')
            self.stamp_packet_receiver = None

        # Remove ip6tables rule for STAMP packets
        # rule_exists = os.system('ip6tables -t raw -C PREROUTING -p udp '
        #                         '--dport {port} -j DROP >/dev/null 2>&1'
        #                         .format(port=self.sender_udp_port)) == 0
        # if rule_exists:
        #     logger.info('Clearing ip6tables rule for STAMP packets')
        #     os.system('ip6tables -t raw -D PREROUTING -p udp --dport {port} '
        #               '-j DROP'.format(port=self.sender_udp_port))
        # else:
        #     logger.info('ip6tables rule for STAMP packets does not exist. '
        #                 'Skipping')

        # Clear the UDP port
        # logger.info('Clearing port information')
        # self.sender_udp_port = None

        # Close the Scapy socket
        if self.sender_socket is not None:
            logger.info('Closing the socket')
            self.sender_socket.close()
            self.sender_socket = None

        # Clear interface information
        logger.info('Clearing the interface information')
        self.stamp_interfaces = None

        # Clear "is_initialized" flag
        self.is_initialized = False

        # Success
        logger.info('Reset completed')

    def create_stamp_session(self, ssid, reflector_ip,
                             stamp_source_ipv4_address, interval, auth_mode,
                             key_chain, timestamp_format, packet_loss_type,
                             delay_measurement_mode,
                             reflector_udp_port, sender_udp_port):
        """
        Create a new STAMP Session. Newly created sessions are in non-running
        state. To start a session, you need to use the start_stamp_session
        method.

        Parameters
        ----------
        ssid : int
            16-bit Session Segment Identifier (SSID).
        reflector_ip : str
            IP address of the STAMP Session Reflector.
        stamp_source_ipv4_address : str
            IP address to be used as source IPv4 address of the STAMP packets.
            If it is None, the global IPv4 address will be used as source
            IPv4 address.
        interval : int
            Time (in seconds) between two STAMP Test packets.
        auth_mode : utils.AuthenticationMode
            Authentication Mode (i.e. Authenticated or Unauthenticated).
        key_chain : str
            Key chain used for the Authenticated Mode.
        timestamp_format : utils.TimestampFormat
            Format of the timestamp (i.e. NTP or PTPv2).
        packet_loss_type : utils.PacketLossType
            Packet Loss Type (i.e. Round Trip, Near End, Far End).
        delay_measurement_mode : utils.DelayMeasurementMode
            Delay Measurement Mode (i.e. One-Way, Two-Way or Loopback).
        reflector_udp_port : int
            The UDP port to use for sending and receiving STAMP packets.

        Returns
        -------
        None.

        Raises
        ------
        NodeNotInitializedError
            If the STAMP Reflector has not been initialized.
        STAMPSessionExistsError
            If the SSID is already used.
        NotImplementedError
            If the requested feature has not been implemented.
        """

        logger.info('Creating new STAMP Session, SSID %d', ssid)

        # If Sender is not initialized, return an error
        if not self.is_initialized:
            logging.error('Sender node is not initialized')
            raise NodeNotInitializedError

        # Retrieve the STAMP Session from the sessions dict
        logger.debug('Get Session, SSID %d', ssid)
        session = self.stamp_sessions.get(ssid, None)

        # If the session already exists, return an error
        logger.debug('Validate SSID %d', ssid)
        if session is not None:
            logging.error('A session with SSID %d already exists', ssid)
            raise STAMPSessionExistsError(ssid=ssid)

        # Check if SSID is in the valid range
        if ssid < MIN_SSID or ssid > MAX_SSID:
            logging.error('SSID is outside the valid range [{%d}, {%d}]',
                          MIN_SSID, MAX_SSID)
            raise SSIDOutOfRangeError(
                ssid=ssid, min_ssid=MIN_SSID, max_ssid=MAX_SSID)

        # Check Authentication Mode
        if auth_mode == AuthenticationMode.AUTHENTICATION_MODE_HMAC_SHA_256:
            logger.fatal('Authenticated Mode is not implemented')
            raise NotImplementedError

        # Check Delay Measurement Mode
        if delay_measurement_mode == \
                DelayMeasurementMode.DELAY_MEASUREMENT_MODE_ONE_WAY:
            logger.fatal('One-Way Measurement Mode is not implemented')
            raise NotImplementedError  # TODO we need to support this!!!
        elif delay_measurement_mode == \
                DelayMeasurementMode.DELAY_MEASUREMENT_MODE_LOOPBACK:
            logger.fatal('Loopback Measurement Mode is not implemented')
            raise NotImplementedError
        
        # Initializing sender socket
        receiver_socket = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM)
        try:
            receiver_socket.bind((self.stamp_source_ipv4_address, sender_udp_port))
        except OSError as err:
            logger.error('Cannot create UDP socket on (%s:%d): %s', self.stamp_source_ipv4_address, sender_udp_port, err)
            # Return an error to the Controller
            raise InternalError(msg=err)
        logger.debug('Socket configured')

        # Initialize a new STAMP Session
        logger.debug('Initializing a new STAMP Session')
        stamp_session = STAMPSenderSession(
            ssid=ssid,
            reflector_ipv4_addr=reflector_ip,
            reflector_udp_port=reflector_udp_port,
            sender_udp_port=receiver_socket.getsockname()[1],
            auth_mode=auth_mode, key_chain=key_chain,
            timestamp_format=timestamp_format,
            packet_loss_type=packet_loss_type,
            delay_measurement_mode=delay_measurement_mode,
            interval=interval,
            stop_flag=Event(),  # To support stopping the sending thread
            sender_ipv4_addr=stamp_source_ipv4_address
        )
        
        # Add the STAMP session to the STAMP sessions dict
        self.stamp_sessions[ssid] = stamp_session
        self.sender_sockets[ssid] = receiver_socket

        # We return the STAMP parameters to inform the caller about
        # the values chosen by the Sender for the optional parameters
        logger.info('STAMP Session %d initialized on port %d', ssid, self.stamp_sessions[ssid].sender_send_port)
        return reflector_ip, reflector_udp_port, auth_mode, key_chain, \
            timestamp_format, packet_loss_type, delay_measurement_mode

    def start_stamp_session(self, ssid, only_collector=True):
        """
        Start an existing STAMP Session.

        Parameters
        ----------
        ssid : int
            16-bit Session Segment Identifier (SSID).

        Returns
        -------
        None.

        Raises
        ------
        NodeNotInitializedError
            If the STAMP Reflector has not been initialized.
        STAMPSessionNotFoundError
            If the STAMP Session does not exist.
        STAMPSessionRunningError
            If the STAMP Session is already running.
        """

        logger.info('Starting STAMP Session, SSID %d', ssid)

        # If Sender is not initialized, return an error
        if not self.is_initialized:
            logging.error('Sender node is not initialized')
            raise NodeNotInitializedError

        # Retrieve the STAMP Session from the sessions dict
        logger.debug('Get Session, SSID %d', ssid)
        session = self.stamp_sessions[ssid]

        # If the session does not exist, return an error
        logger.debug('Validate SSID %d', ssid)
        if session is None:
            logging.error('SSID %d not found', ssid)
            raise STAMPSessionNotFoundError(ssid=ssid)

        # If the session is already running, return an error
        logger.debug('Checking if session is running, SSID %d', ssid)
        if session.is_running:
            logging.error('Cannot start STAMP Session (SSID %d): Session '
                          'already running', ssid)
            raise STAMPSessionNotRunningError(ssid=ssid)

        # Create a new thread to handle the asynchronous periodic sending of
        # STAMP Test packets
        logger.debug('Creating sending thread')
        self.sending_thread[ssid] = Thread(
            target=self.send_stamp_packet_periodic,
            kwargs={
                'ssid': ssid,
                'interval': session.interval
            }
        )

        # Start the sending thread
        logger.debug('Starting sending thread')
        session.stop_flag.clear()
        if not only_collector:
            self.sending_thread[ssid].start()

        # Set the flag "started"
        session.set_started()

        # Success
        logger.debug('STAMP Session (SSID %d) started', ssid)

    def sender_receiver_wrapper(self, ssid, reciever_socket):
        reciever_socket.setblocking(0)
        while self.stamp_sessions[ssid].is_running:
            if select.select([reciever_socket], [], [], 0.1)[0]:
                raw_data, sender_addr = reciever_socket.recvfrom(44) # buffer size is 44 bytes
                logger.debug('Packet recieved from %s:%d', sender_addr[0], sender_addr[1])
                self.stamp_reply_packet_received(raw_data)    

    def stop_stamp_session(self, ssid):
        """
        Stop a running STAMP Session.

        Parameters
        ----------
        ssid : int
            16-bit Session Segment Identifier (SSID).

        Returns
        -------
        None.

        Raises
        ------
        STAMPSessionNotFoundError
            If the STAMP Session does not exist.
        STAMPSessionNotRunningError
            If the STAMP Session is not running.
        """

        logger.info('Stopping STAMP Session, SSID %d', ssid)

        # Retrieve the STAMP Session from the sessions dict
        logger.debug('Get Session, SSID %d', ssid)
        session = self.stamp_sessions.get(ssid, None)

        # If the session does not exist, return an error
        logger.debug('Validate SSID %d', ssid)
        if session is None:
            logging.error('SSID %d not found', ssid)
            raise STAMPSessionNotFoundError(ssid=ssid)

        # If the session is not running, return an error
        logger.debug('Checking if session is running, SSID %d', ssid)
        if not session.is_running:
            logging.error('Cannot stop STAMP Session (SSID %d): Session '
                          'not running', ssid)
            raise STAMPSessionNotRunningError(ssid=ssid)

        # Stop the sending thread
        logger.debug('Stopping sending thread')
        session.stop_flag.set()
        self.sending_thread[ssid].join()
        del self.sending_thread[ssid]

        # Clear the flag "started"
        session.clear_started()

        # Stop reciver thread
        # self.reciver_thread[ssid].join()
        # del self.reciver_thread[ssid]

        # Success
        logger.debug('STAMP Session (SSID %d) stopped', ssid)

    def destroy_stamp_session(self, ssid):
        """
        Remove an existing STAMP Session. The session must not be running.

        Parameters
        ----------
        ssid : int
            16-bit Session Segment Identifier (SSID).

        Returns
        -------
        None.

        Raises
        ------
        NodeNotInitializedError
            If the STAMP Reflector has not been initialized.
        STAMPSessionNotFoundError
            If the STAMP Session does not exist.
        STAMPSessionRunningError
            If the STAMP Session is running.
        """

        logger.info('Removing STAMP Session %d', ssid)

        # If Sender is not initialized, return an error
        if not self.is_initialized:
            logging.error('Sender node is not initialized')
            raise NodeNotInitializedError

        # Retrieve the STAMP Session from the sessions dict
        logger.debug('Get Session, SSID %d', ssid)
        session = self.stamp_sessions.get(ssid, None)

        # If the session does not exist, return an error
        logger.debug('Validate SSID %d', ssid)
        if session is None:
            logging.error('SSID %d not found', ssid)
            raise STAMPSessionNotFoundError(ssid=ssid)

        # If the session is running, we cannot destory it and we need to
        # return an error
        logger.debug('Checking if session is running, SSID %d', ssid)
        if session.is_running:
            logging.error('Cannot destroy STAMP Session (SSID %d): Session '
                          'is currently running', ssid)
            raise STAMPSessionRunningError(ssid=ssid)

        # Remove the STAMP session from the list of existing sessions
        del self.stamp_sessions[ssid]

        # remove reciver socket
        self.sender_sockets[ssid].close()
        del self.sender_sockets[ssid]

        # Success
        logger.debug('STAMP Session (SSID %d) destroyed', ssid)

    def get_stamp_session_results(self, ssid):
        """
        Collect the results of a STAMP Session.

        Parameters
        ----------
        ssid : int
            16-bit Session Segment Identifier (SSID).

        Returns
        -------
        results : list
            The list of results. Each result is represented as a dict.
            Example: {
                'ssid': 101,
                'test_pkt_tx_timestamp': 1635958467.2059603,
                'reply_pkt_tx_timestamp': 1635958467.213707,
                'reply_pkt_rx_timestamp': 1635958467.523983,
                'test_pkt_rx_timestamp': 1635958467.213707
            }

        Raises
        ------
        NodeNotInitializedError
            If the STAMP Reflector has not been initialized.
        STAMPSessionNotFoundError
            If the STAMP Session does not exist.
        """

        #logger.debug('Getting results from STAMP Session %d', ssid)

        # If Sender is not initialized, return an error
        if not self.is_initialized:
            logging.error('Sender node is not initialized')
            raise NodeNotInitializedError

        # Retrieve the STAMP Session from the sessions dict
        #logger.debug('Get STAMP Session, SSID %d', ssid)
        session = self.stamp_sessions.get(ssid, None)

        # If the session does not exist, return an error
        #logger.debug('Validate SSID %d', ssid)
        if session is None:
            logging.error('SSID %d not found', ssid)
            raise STAMPSessionNotFoundError(ssid=ssid)

        # Prepare the results list
        results = list()

        # Populate the results list with the test results
        for result in session.get_test_results():
            results.append({
                'ssid': result.ssid,
                'test_pkt_tx_timestamp': result.test_pkt_tx_timestamp,
                'reply_pkt_tx_timestamp': result.reply_pkt_tx_timestamp,
                'reply_pkt_rx_timestamp': result.reply_pkt_rx_timestamp,
                'test_pkt_rx_timestamp': result.test_pkt_rx_timestamp
            })

        # Set status code and return
        #logger.info('Returning %d results for STAMP session %d)',len(results), ssid)
        return results
    


# class STAMPSessionSenderServicer(
#         stamp_sender_pb2_grpc.STAMPSessionSenderService):
#     """
#     Provides methods that allow a controller to control the STAMP Session
#     Sender through the gRPC protocol.
#     """

#     def __init__(self, stamp_session_sender):
#         # Initialize super class STAMPSessionSenderService
#         super().__init__()
#         # Reference to the STAMPSessionSender to be controlled through the
#         # gRPC interface
#         self.stamp_session_sender = stamp_session_sender

#     def Init(self, request, context):
#         """RPC used to configure the Session Sender."""

#         logger.debug('Init RPC invoked. Request: %s', request)

#         # Extract STAMP Source IPv6 address from the request message
#         # This parameter is optional, therefore we set it to None if it is
#         # not provided
#         stamp_source_ipv6_address = None
#         if request.stamp_source_ipv6_address:
#             stamp_source_ipv6_address = request.stamp_source_ipv6_address

#         # Try to initialize the Session Sender
#         try:
#             self.stamp_session_sender.init(
#                 sender_udp_port=request.sender_udp_port,
#                 interfaces=list(request.interfaces),
#                 stamp_source_ipv6_address=stamp_source_ipv6_address
#             )
#         except NodeInitializedError:
#             # The node has already been initialized, return an error
#             logging.error('Cannot complete the requested operation: '
#                           'Sender node has been already initialized')
#             return stamp_sender_pb2.InitStampSenderReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_ALREADY_INITIALIZED,
#                 description='Sender node has been already initialized')
#         except InvalidArgumentError:
#             # The provided UDP port is not valid, return an error
#             logging.error('Cannot complete the requested operation: '
#                           'Invalid UDP port %d', request.sender_udp_port)
#             return stamp_sender_pb2.InitStampSenderReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_INVALID_ARGUMENT,
#                 description='Invalid UDP port {port}'
#                             .format(port=request.sender_udp_port))
#         except InternalError as err:
#             # Failed to create a UDP socket, return an error
#             logging.error('Cannot complete the requested operation: '
#                           'Cannot create UDP socket: %s', err.msg)
#             # Return an error to the Controller
#             return stamp_sender_pb2.InitStampSenderReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR,
#                 description='Cannot create UDP socket: {err}'
#                             .format(err=err.msg))

#         # Return with success status code
#         logger.debug('Init RPC completed')
#         return stamp_sender_pb2.InitStampSenderReply(
#             status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

#     def Reset(self, request, context):
#         """RPC used to reset the Session Sender."""

#         logger.debug('Reset RPC invoked. Request: %s', request)
#         logger.info('Attempting to reset STAMP node')

#         # Reset the Session Sender. If there are sessions, the reset operation
#         # cannot be performed and we return an error to the controller
#         try:
#             self.stamp_session_sender.reset()
#         except ResetSTAMPNodeError:
#             logging.error('Reset RPC failed')
#             return stamp_sender_pb2.ResetStampSenderReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_RESET_FAILED,
#                 description='Cannot execute Reset command: One or more STAMP '
#                             'Sessions exist. Destroy all STAMP Sessions '
#                             'before resetting the node.')

#         # Return with success status code
#         logger.info('Reset RPC completed')
#         logger.debug('Reset RPC completed')
#         return stamp_sender_pb2.ResetStampSenderReply(
#             status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

#     def CreateStampSession(self, request, context):
#         """RPC used to create a new STAMP Session."""

#         logger.debug('CreateStampSession RPC invoked. Request: %s', request)

#         # Extract STAMP Source IPv6 address from the request message
#         # This parameter is optional, therefore we set it to None if it is
#         # not provided
#         stamp_source_ipv6_address = None
#         if request.stamp_source_ipv6_address:
#             stamp_source_ipv6_address = request.stamp_source_ipv6_address

#         # Parse optional parameters
#         # If an optional parameter has not been set, we use the default value
#         auth_mode = grpc_to_py_resolve_defaults(
#             AuthenticationMode, request.stamp_params.auth_mode)
#         key_chain = request.stamp_params.key_chain
#         timestamp_format = grpc_to_py_resolve_defaults(
#             TimestampFormat, request.stamp_params.timestamp_format)
#         packet_loss_type = grpc_to_py_resolve_defaults(
#             PacketLossType, request.stamp_params.packet_loss_type)
#         delay_measurement_mode = grpc_to_py_resolve_defaults(
#             DelayMeasurementMode, request.stamp_params.delay_measurement_mode)

#         # Try to create a STAMP Session
#         try:
#             _, _, auth_mode, key_chain, \
#                 timestamp_format, packet_loss_type, delay_measurement_mode = \
#                 self.stamp_session_sender.create_stamp_session(
#                     ssid=request.ssid,
#                     reflector_ip=request.stamp_params.reflector_ip,
#                     stamp_source_ipv6_address=stamp_source_ipv6_address,
#                     interval=request.interval, auth_mode=auth_mode,
#                     key_chain=key_chain, timestamp_format=timestamp_format,
#                     packet_loss_type=packet_loss_type,
#                     delay_measurement_mode=delay_measurement_mode,
#                     reflector_udp_port=request.stamp_params.reflector_udp_port,
#                     segments=list(request.sidlist.segments)
#                 )
#         except NodeNotInitializedError:
#             # The Reflector is not initialized
#             # To create the STAMP Session, the Reflector node needs to be
#             # initialized
#             logging.error('Sender node is not initialized')
#             return stamp_sender_pb2.CreateStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_NOT_INITIALIZED,
#                 description='Sender node is not initialized')
#         except STAMPSessionExistsError:
#             # SSID is already used, return an error
#             logging.error('A session with SSID %d already exists',
#                           request.ssid)
#             return stamp_sender_pb2.CreateStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_SESSION_EXISTS,
#                 description='A session with SSID {ssid} already exists'
#                             .format(ssid=request.ssid))
#         except SSIDOutOfRangeError:
#             # SSID is outside the valid range, return an error
#             logging.error('SSID is outside the valid range [{%d}, {%d}]',
#                           MIN_SSID, MAX_SSID)
#             return stamp_sender_pb2.CreateStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_INVALID_ARGUMENT,
#                 description='SSID is outside the valid range '
#                             '[{min_ssid}, {max_ssid}]'
#                             .format(min_ssid=MIN_SSID, max_ssid=MAX_SSID))

#         # Create the reply message
#         reply = stamp_sender_pb2.CreateStampSenderSessionReply()

#         # Fill the reply with the STAMP parameters
#         # We report the STAMP parameters to the controller to inform it about
#         # the values chosen by the Sender for the optional parameters
#         reply.stamp_params.reflector_ip = request.stamp_params.reflector_ip
#         reply.stamp_params.reflector_udp_port = \
#             request.stamp_params.reflector_udp_port
#         reply.stamp_params.auth_mode = py_to_grpc(
#             AuthenticationMode, auth_mode)
#         reply.stamp_params.key_chain = key_chain
#         reply.stamp_params.timestamp_format = py_to_grpc(
#             TimestampFormat, timestamp_format)
#         reply.stamp_params.packet_loss_type = py_to_grpc(
#             PacketLossType, packet_loss_type)
#         reply.stamp_params.delay_measurement_mode = py_to_grpc(
#             DelayMeasurementMode, delay_measurement_mode)

#         # Set success status code
#         reply.status = common_pb2.StatusCode.STATUS_CODE_SUCCESS

#         # Return with success status code
#         logger.debug('CreateStampSession RPC completed')
#         return reply

#     def StartStampSession(self, request, context):
#         """RPC used to start a STAMP Session."""

#         logger.debug('StartStampSession RPC invoked. Request: %s', request)

#         # Try to start the STAMP Session
#         try:
#             self.stamp_session_sender.start_stamp_session(ssid=request.ssid)
#         except NodeNotInitializedError:
#             # The Reflector is not initialized
#             logging.error('Sender node is not initialized')
#             return stamp_sender_pb2.StartStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_NOT_INITIALIZED,
#                 description='Sender node is not initialized')
#         except STAMPSessionNotFoundError:
#             # The STAMP Session does not exist
#             logging.error('SSID %d not found', request.ssid)
#             return stamp_sender_pb2.StartStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND,
#                 description='SSID {ssid} not found'.format(ssid=request.ssid))
#         except STAMPSessionRunningError:
#             # The STAMP Session is currently running; we cannot start an
#             # already running session
#             logging.error('Cannot start STAMP Session (SSID %d): Session '
#                           'already running', request.ssid)
#             return stamp_sender_pb2.StartStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_SESSION_RUNNING,
#                 description='STAMP Session (SSID {ssid}) already running'
#                 .format(ssid=request.ssid))

#         # Return with success status code
#         logger.debug('StartStampSessionReply RPC completed')
#         return stamp_sender_pb2.StartStampSenderSessionReply(
#             status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

#     def StopStampSession(self, request, context):
#         """RPC used to stop a running STAMP Session."""

#         logger.debug('StopStampSession RPC invoked. Request: %s', request)

#         # Try to stop the STAMP Session
#         try:
#             self.stamp_session_sender.stop_stamp_session(ssid=request.ssid)
#         except STAMPSessionNotFoundError:
#             # The STAMP Session does not exist
#             logging.error('SSID %d not found', request.ssid)
#             return stamp_sender_pb2.StopStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND,
#                 description='SSID {ssid} not found'.format(ssid=request.ssid))
#         except STAMPSessionNotRunningError:
#             # The STAMP Session is currently running; we cannot stop a
#             # non-running session
#             logging.error('Cannot stop STAMP Session (SSID %d): Session '
#                           'not running', request.ssid)
#             return stamp_sender_pb2.StopStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_RUNNING,
#                 description='STAMP Session (SSID {ssid}) is not running'
#                 .format(ssid=request.ssid))

#         # Return with success status code
#         logger.debug('StopStampSession RPC completed')
#         return stamp_sender_pb2.StopStampSenderSessionReply(
#             status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

#     def DestroyStampSession(self, request, context):
#         """RPC used to destroy an existing STAMP Session."""

#         logger.debug('DestroyStampSession RPC invoked. Request: %s', request)

#         # Try to destroy the STAMP Session
#         try:
#             self.stamp_session_sender.destroy_stamp_session(ssid=request.ssid)
#         except NodeNotInitializedError:
#             # The Reflector is not initialized
#             logging.error('Sender node is not initialized')
#             return stamp_sender_pb2.DestroyStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_NOT_INITIALIZED,
#                 description='Sender node is not initialized')
#         except STAMPSessionNotFoundError:
#             # The STAMP Session does not exist
#             logging.error('SSID %d not found', request.ssid)
#             return stamp_sender_pb2.DestroyStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND,
#                 description='SSID {ssid} not found'.format(ssid=request.ssid))
#         except STAMPSessionRunningError:
#             # The STAMP Session is currently running; we cannot destroy a
#             # running session
#             logging.error('Cannot destroy STAMP Session (SSID %d): Session '
#                           'is currently running', request.ssid)
#             return stamp_sender_pb2.DestroyStampSenderSessionReply(
#                 status=common_pb2.StatusCode.STATUS_CODE_SESSION_RUNNING,
#                 description='STAMP Session (SSID {ssid}) is running'
#                 .format(ssid=request.ssid))

#         # Return with success status code
#         logger.debug('DestroyStampSession RPC completed')
#         return stamp_sender_pb2.DestroyStampSenderSessionReply(
#             status=common_pb2.StatusCode.STATUS_CODE_SUCCESS)

#     def GetStampSessionResults(self, request, context):
#         """RPC used to collect the results of STAMP Session."""

#         logger.debug('GetStampTestResults RPC invoked. Request: %s', request)

#         # Try to collect the results of the STAMP Session
#         try:
#             results = self.stamp_session_sender.get_stamp_session_results(
#                 ssid=request.ssid)
#         except NodeNotInitializedError:
#             # The Reflector is not initialized
#             logging.error('Sender node is not initialized')
#             return stamp_sender_pb2.StampResults(
#                 status=common_pb2.StatusCode.STATUS_CODE_NOT_INITIALIZED,
#                 description='Sender node is not initialized')
#         except STAMPSessionNotFoundError:
#             # The STAMP Session does not exist
#             logging.error('SSID %d not found', request.ssid)
#             return stamp_sender_pb2.StampResults(
#                 status=common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND,
#                 description='SSID {ssid} not found'.format(ssid=request.ssid))

#         # Prepare the gRPC reply
#         reply = stamp_sender_pb2.StampResults()

#         # Populate the gRPC reply with the test results
#         for result in results:
#             res = reply.results.add()
#             res.ssid = result['ssid']
#             res.test_pkt_tx_timestamp = result['test_pkt_tx_timestamp']
#             res.reply_pkt_tx_timestamp = result['reply_pkt_tx_timestamp']
#             res.reply_pkt_rx_timestamp = result['reply_pkt_rx_timestamp']
#             res.test_pkt_rx_timestamp = result['test_pkt_rx_timestamp']

#         # Set status code and return
#         logger.debug('StampResults RPC completed')
#         reply.status = common_pb2.StatusCode.STATUS_CODE_SUCCESS
#         return reply

#     def GetResultsCounter(self, request, context):

#         num_results = len(self.stamp_session_sender.get_stamp_session_results(ssid=request.ssid))

#         reply = stamp_sender_pb2.StampResultsCountersReply(status=common_pb2.StatusCode.STATUS_CODE_SUCCESS, num_results=num_results)
#         import queue
#         self.stamp_session_sender.stamp_sessions.get(request.ssid).test_results = queue.Queue()

#         return reply


# def run_grpc_server(grpc_ip: str = None, grpc_port: int = DEFAULT_GRPC_PORT,
#                     secure_mode=False, server=None, stop_event=None):
#     """
#     Run a gRPC server that will accept RPCs on the provided IP address and
#      port and block until the server is terminated.

#     Parameters
#     ----------
#     grpc_ip : str, optional
#         IP address on which the gRPC server will accept connections. None
#          means "any" (default is None)
#     grpc_port : int, optional
#         Port on which the gRPC server will accept connections
#          (default is 12345).
#     secure_mode : bool, optional
#         Whether to enable or not gRPC secure mode (default is False).
#     server : optional
#         An existing gRPC server. If None, a new gRPC server is created.
#     stop_event : threading.event, optional
#         Stop event. If set, something has requested the termination of
#         the device and we need to gracefully shutdown the reflector.

#     Returns
#     -------
#     None
#     """

#     # Create a STAMP Session Sender object
#     stamp_session_sender = STAMPSessionSender(stop_event)

#     # If a reference to an existing gRPC server has been passed as argument,
#     # attach the gRPC interface to the existing server
#     if server is not None:
#         stamp_sender_pb2_grpc.add_STAMPSessionSenderServiceServicer_to_server(
#             STAMPSessionSenderServicer(stamp_session_sender), server)
#         return stamp_session_sender

#     # Create the gRPC server
#     logger.debug('Creating the gRPC server')
#     server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
#     stamp_sender_pb2_grpc.add_STAMPSessionSenderServiceServicer_to_server(
#         STAMPSessionSenderServicer(stamp_session_sender), server)

#     # Add secure or insecure port, depending on the "secure_mode" chosen
#     if secure_mode:
#         logging.fatal('Secure mode not yet implemented')
#         exit(1)
#     else:
#         # If gRPC IP address is not provided, listen on any IP address
#         if grpc_ip is None:
#             # Listen on any IPv4 address
#             server.add_insecure_port('0.0.0.0:{port}'.format(port=grpc_port))
#             # Listen on any IPv6 address
#             server.add_insecure_port('[::]:{port}'.format(port=grpc_port))
#         else:
#             server.add_insecure_port('{address}:{port}'.format(
#                 address=grpc_ip, port=grpc_port))

#     # Start the server and block until it is terminated
#     logger.info('Listening gRPC, port %d', grpc_port)
#     server.start()
#     server.wait_for_termination()


# def parse_arguments():
#     """
#     This function parses the command-line arguments.

#     Returns
#     -------
#     None.
#     """

#     parser = argparse.ArgumentParser(
#         description='STAMP Session Sender implementation.')
#     parser.add_argument('--grpc-ip', dest='grpc_ip', type=str,
#                         help='ip address on which the gRPC server will accept '
#                              'RPCs. None means "any" (default: None)')
#     parser.add_argument('--grpc-port', dest='grpc_port', type=int,
#                         default=DEFAULT_GRPC_PORT,
#                         help='port on which the gRPC server will accept RPCs '
#                              '(default: 12345)')
#     parser.add_argument('-d', '--debug', dest='debug', action='store_true',
#                         default=False, help='Debug mode (default: False')
#     args = parser.parse_args()

#     return args


# if __name__ == '__main__':

#     # Parse and extract command-line arguments
#     logger.debug('Parsing arguments')
#     args = parse_arguments()
#     grpc_ip = args.grpc_ip
#     grpc_port = args.grpc_port
#     debug = args.debug

#     # Configure logging
#     if debug:
#         logger.setLevel(level=logging.DEBUG)
#         logger.info('Logging level: DEBUG')
#     else:
#         logger.setLevel(level=logging.INFO)
#         logger.info('Logging level: INFO')

#     # Run the gRPC server and block forever
#     logger.debug('Starting gRPC server')
#     run_grpc_server(grpc_ip, grpc_port)
