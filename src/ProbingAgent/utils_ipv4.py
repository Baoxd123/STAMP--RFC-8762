#!/usr/bin/python

##########################################################################
# Copyright (C) 2021 Carmine Scarpitta - (University of Rome "Tor Vergata")
# www.uniroma2.it/netgroup
#
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Utils for SRv6 Delay Measurement
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""Utils for SRv6 Delay Measurement"""

from ipaddress import (
    IPv4Interface,
    IPv6Interface,
    AddressValueError
)

from socket import AF_INET, AF_INET6

import enum
import queue
import logging

# import common_pb2
from .stamp import (
    AuthenticationMode,
    DelayMeasurementMode,
    PacketLossType,
    SessionReflectorMode,
    TimestampFormat)


# Maximum STAMP Sequence Number
MAX_SEQUENCE_NUMBER = 2**32 - 1

# Minimum STAMP Session Identifier (SSID)
MIN_SSID = 0

# Maximum STAMP Session Identifier (SSID)
MAX_SSID = 2**16 - 1


# Constants related to the STAMP packets

# Offset of the Next Header field of the IPv6 header relative to the IPv6
# packet
NEXT_HEADER_IPV6_OFFSET = 6

# Protocol Number associated to "Routing Header for IPv6"
ROUTING_HEADER_PROTOCOL_NUMBER = 43

# Offset of the SRH relative to the IPv6 packet for our STAMP packets
SRH_OFFSET = 40

# Offset of the Next Header field of the SRv6 header (SRH) relative to the SRH
NEXT_HEADER_SRH_OFFSET = 0

# Offset of Protocol field relative to IPv4 header
IPV4_PROTOCOL_OFFSET = 9

# UDP protocol number
UDP_PROTOCOL_NUMBER = 17

# Offset of the Header Extension Length field in the SRv6 Header (SRH)
# relative to the SRH
HDR_EXT_LEN_SRH_OFFSET = 1

# Offset of the UDP Destination Port field relative to the UDP Header
UDP_DEST_PORT_OFFSET = 2

# Size (in bytes) of the UDP Destination Port field
UDP_DEST_PORT_LENGTH = 2

# Next Header value of the IPv6 header
NEXT_HEADER_IPV6_FIELD = 'ip6[%d]' % NEXT_HEADER_IPV6_OFFSET

# Next Header value of the SRv6 Header
NEXT_HEADER_SRH_FIELD = 'ip6[%d]' % (SRH_OFFSET + NEXT_HEADER_SRH_OFFSET)

# Header Extension Length value of the SRv6 Header
HDR_EXT_LEN_SRH_FIELD = 'ip6[%d]' % (SRH_OFFSET + HDR_EXT_LEN_SRH_OFFSET)

# Length of the SRv6 Header
SRH_LENGTH = '8 + ' + HDR_EXT_LEN_SRH_FIELD + '* 8'

# Offset of the UDP Header relative to the IPv6+SRH packet
UDP_HEADER_OFFSET = str(SRH_OFFSET) + SRH_LENGTH

# UDP Destination Port value
UDP_DEST_PORT_FIELD = 'ip6[%d + %s + %d : %d]' % (
    SRH_OFFSET, SRH_LENGTH, UDP_DEST_PORT_OFFSET, UDP_DEST_PORT_LENGTH)


class StatusCode(enum.Enum):
    """Status Code returned by an RPC."""

    # Status code not specified
    STATUS_CODE_UNSPECIFIED = 'unspec'

    # Operation is successfully
    STATUS_CODE_SUCCESS = 'success'

    # STAMP Session not found
    STATUS_CODE_SESSION_NOT_FOUND = 'session-not-found'

    # STAMP Session already exists
    STATUS_CODE_SESSION_EXISTS = 'session-exists'

    # An invalid argument has been provided
    STATUS_CODE_INVALID_ARGUMENT = 'invalid-argument'

    # STAMP Session is running
    STATUS_CODE_SESSION_RUNNING = 'session-running'

    # STAMP Session is not running
    STATUS_CODE_SESSION_NOT_RUNNING = 'session-not-running'

    # Node is not initialized
    STATUS_CODE_NOT_INITIALIZED = 'not-initialized'

    # Node has been already initialized
    STATUS_CODE_ALREADY_INITIALIZED = 'already-initialized'

    # An error occurred during a Reset operation
    STATUS_CODE_RESET_FAILED = 'reset-failed'

    # An internal error occurred
    STATUS_CODE_INTERNAL_ERROR = 'internal-error'


# Mapping gRPC values to Python values

# AUTH_MODE_GRPC_TO_PY = {
#     common_pb2.AuthenticationMode.AUTHENTICATION_MODE_UNSPECIFIED:
#     AuthenticationMode.AUTHENTICATION_MODE_UNSPECIFIED.value,
#     common_pb2.AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED:
#     AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
#     common_pb2.AuthenticationMode.AUTHENTICATION_MODE_HMAC_SHA_256:
#     AuthenticationMode.AUTHENTICATION_MODE_HMAC_SHA_256.value,
# }

# TIMESTAMP_FORMAT_GRPC_TO_PY = {
#     common_pb2.TimestampFormat.TIMESTAMP_FORMAT_UNSPECIFIED:
#     TimestampFormat.TIMESTAMP_FORMAT_UNSPECIFIED.value,
#     common_pb2.TimestampFormat.TIMESTAMP_FORMAT_NTP:
#     TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
#     common_pb2.TimestampFormat.TIMESTAMP_FORMAT_PTPv2:
#     TimestampFormat.TIMESTAMP_FORMAT_PTPv2.value,
# }

# PACKET_LOSS_TYPE_GRPC_TO_PY = {
#     common_pb2.PacketLossType.PACKET_LOSS_TYPE_UNSPECIFIED:
#     PacketLossType.PACKET_LOSS_TYPE_UNSPECIFIED.value,
#     common_pb2.PacketLossType.PACKET_LOSS_TYPE_ROUND_TRIP:
#     PacketLossType.PACKET_LOSS_TYPE_ROUND_TRIP.value,
#     common_pb2.PacketLossType.PACKET_LOSS_TYPE_NEAR_END:
#     PacketLossType.PACKET_LOSS_TYPE_NEAR_END.value,
#     common_pb2.PacketLossType.PACKET_LOSS_TYPE_FAR_END:
#     PacketLossType.PACKET_LOSS_TYPE_FAR_END.value,
# }

# DELAY_MEASUREMENT_MODE_GRPC_TO_PY = {
#     common_pb2.DelayMeasurementMode.DELAY_MEASUREMENT_MODE_UNSPECIFIED:
#     DelayMeasurementMode.DELAY_MEASUREMENT_MODE_UNSPECIFIED.value,
#     common_pb2.DelayMeasurementMode.DELAY_MEASUREMENT_MODE_ONE_WAY:
#     DelayMeasurementMode.DELAY_MEASUREMENT_MODE_ONE_WAY.value,
#     common_pb2.DelayMeasurementMode.DELAY_MEASUREMENT_MODE_TWO_WAY:
#     DelayMeasurementMode.DELAY_MEASUREMENT_MODE_TWO_WAY.value,
#     common_pb2.DelayMeasurementMode.DELAY_MEASUREMENT_MODE_LOOPBACK:
#     DelayMeasurementMode.DELAY_MEASUREMENT_MODE_LOOPBACK.value,
# }

# SESSION_REFLECTOR_MODE_GRPC_TO_PY = {
#     common_pb2.SessionReflectorMode.SESSION_REFLECTOR_MODE_UNSPECIFIED:
#     SessionReflectorMode.SESSION_REFLECTOR_MODE_UNSPECIFIED.value,
#     common_pb2.SessionReflectorMode.SESSION_REFLECTOR_MODE_STATELESS:
#     SessionReflectorMode.SESSION_REFLECTOR_MODE_STATELESS.value,
#     common_pb2.SessionReflectorMode.SESSION_REFLECTOR_MODE_STATEFUL:
#     SessionReflectorMode.SESSION_REFLECTOR_MODE_STATEFUL.value,
# }

# STATUS_CODE_GRPC_TO_PY = {
#     common_pb2.StatusCode.STATUS_CODE_UNSPECIFIED:
#     StatusCode.STATUS_CODE_UNSPECIFIED.value,
#     common_pb2.StatusCode.STATUS_CODE_SUCCESS:
#     StatusCode.STATUS_CODE_SUCCESS.value,
#     common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_FOUND:
#     StatusCode.STATUS_CODE_SESSION_NOT_FOUND.value,
#     common_pb2.StatusCode.STATUS_CODE_SESSION_EXISTS:
#     StatusCode.STATUS_CODE_SESSION_EXISTS.value,
#     common_pb2.StatusCode.STATUS_CODE_INVALID_ARGUMENT:
#     StatusCode.STATUS_CODE_INVALID_ARGUMENT.value,
#     common_pb2.StatusCode.STATUS_CODE_SESSION_RUNNING:
#     StatusCode.STATUS_CODE_SESSION_RUNNING.value,
#     common_pb2.StatusCode.STATUS_CODE_SESSION_NOT_RUNNING:
#     StatusCode.STATUS_CODE_SESSION_NOT_RUNNING.value,
#     common_pb2.StatusCode.STATUS_CODE_NOT_INITIALIZED:
#     StatusCode.STATUS_CODE_NOT_INITIALIZED.value,
#     common_pb2.StatusCode.STATUS_CODE_ALREADY_INITIALIZED:
#     StatusCode.STATUS_CODE_ALREADY_INITIALIZED.value,
#     common_pb2.StatusCode.STATUS_CODE_RESET_FAILED:
#     StatusCode.STATUS_CODE_RESET_FAILED.value,
#     common_pb2.StatusCode.STATUS_CODE_INTERNAL_ERROR:
#     StatusCode.STATUS_CODE_INTERNAL_ERROR.value,
# }


# Mapping Python values to gRPC values

# AUTH_MODE_PY_TO_GRPC = {py: grpc for (
#     grpc, py) in AUTH_MODE_GRPC_TO_PY.items()}
# TIMESTAMP_FORMAT_PY_TO_GRPC = {py: grpc for (
#     grpc, py) in TIMESTAMP_FORMAT_GRPC_TO_PY.items()}
# PACKET_LOSS_TYPE_PY_TO_GRPC = {py: grpc for (
#     grpc, py) in PACKET_LOSS_TYPE_GRPC_TO_PY.items()}
# DELAY_MEASUREMENT_MODE_PY_TO_GRPC = {py: grpc for (
#     grpc, py) in DELAY_MEASUREMENT_MODE_GRPC_TO_PY.items()}
# SESSION_REFLECTOR_MODE_PY_TO_GRPC = {py: grpc for (
#     grpc, py) in SESSION_REFLECTOR_MODE_GRPC_TO_PY.items()}
# STATUS_CODE_PY_TO_GRPC = {py: grpc for (
#     grpc, py) in STATUS_CODE_GRPC_TO_PY.items()}


# Default values
DEFAULT_AUTH_MODE = \
    AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value
DEFAULT_TIMESTAMP_FORMAT = TimestampFormat.TIMESTAMP_FORMAT_NTP.value
DEFAULT_PACKET_LOSS_TYPE = PacketLossType.PACKET_LOSS_TYPE_ROUND_TRIP.value
DEFAULT_DELAY_MEASUREMENT_MODE = \
    DelayMeasurementMode.DELAY_MEASUREMENT_MODE_TWO_WAY.value
DEFAULT_SESSION_REFLECTOR_MODE = \
    SessionReflectorMode.SESSION_REFLECTOR_MODE_STATELESS.value
DEFAULT_STATUS_CODE = StatusCode.STATUS_CODE_UNSPECIFIED.value


def grpc_tp_py(type, value_grpc):
    """
    Convert a gRPC value to the corresponding Python value.

    Parameters
    ----------
    type : enum.Enum
        Type of the gRPC value.
    value_grpc : google.protobuf.internal.enum_type_wrapper.EnumTypeWrapper
        gRPC value to convert.

    Returns
    -------
    value_py : bool
        Python value.
    """

    # if type == AuthenticationMode:
    #     return AUTH_MODE_GRPC_TO_PY[value_grpc]
    # if type == TimestampFormat:
    #     return TIMESTAMP_FORMAT_GRPC_TO_PY[value_grpc]
    # if type == PacketLossType:
    #     return PACKET_LOSS_TYPE_GRPC_TO_PY[value_grpc]
    # if type == DelayMeasurementMode:
    #     return DELAY_MEASUREMENT_MODE_GRPC_TO_PY[value_grpc]
    # if type == SessionReflectorMode:
    #     return SESSION_REFLECTOR_MODE_GRPC_TO_PY[value_grpc]
    # if type == StatusCode:
    #     return STATUS_CODE_GRPC_TO_PY[value_grpc]


def grpc_to_py_resolve_defaults(type, value_grpc):
    """
    Convert a gRPC value to the corresponding Python value. Similar to
     grpc_tp_py, but this function also resolves the UNSPEC values to the
     corresponding default values.

    Parameters
    ----------
    type : enum.Enum
        Type of the gRPC value.
    value_grpc : google.protobuf.internal.enum_type_wrapper.EnumTypeWrapper
        gRPC value to convert.

    Returns
    -------
    value_py : str
        Python value.
    """

    if type == AuthenticationMode:
        value_py = grpc_tp_py(type, value_grpc)
        if value_py == \
                AuthenticationMode.AUTHENTICATION_MODE_UNSPECIFIED.value:
            return DEFAULT_AUTH_MODE
        return value_py
    if type == TimestampFormat:
        value_py = grpc_tp_py(type, value_grpc)
        if value_py == TimestampFormat.TIMESTAMP_FORMAT_UNSPECIFIED.value:
            return DEFAULT_TIMESTAMP_FORMAT
        return value_py
    if type == PacketLossType:
        value_py = grpc_tp_py(type, value_grpc)
        if value_py == PacketLossType.PACKET_LOSS_TYPE_UNSPECIFIED.value:
            return DEFAULT_PACKET_LOSS_TYPE
        return value_py
    if type == DelayMeasurementMode:
        value_py = grpc_tp_py(type, value_grpc)
        if value_py == \
                DelayMeasurementMode.DELAY_MEASUREMENT_MODE_UNSPECIFIED.value:
            return DEFAULT_DELAY_MEASUREMENT_MODE
        return value_py
    if type == SessionReflectorMode:
        value_py = grpc_tp_py(type, value_grpc)
        if value_py == \
                SessionReflectorMode.SESSION_REFLECTOR_MODE_UNSPECIFIED.value:
            return DEFAULT_SESSION_REFLECTOR_MODE
        return value_py
    if type == StatusCode:
        value_py = grpc_tp_py(type, value_grpc)
        if value_py == StatusCode.STATUS_CODE_UNSPECIFIED.value:
            return DEFAULT_STATUS_CODE
        return value_py


# def py_to_grpc(type, value_py):
#     """
#     Convert a Python value to the corresponding gRPC value.

#     Parameters
#     ----------
#     type : enum.Enum
#         Type of the gRPC value.
#     value_py : str
#         Python value to convert.

#     Returns
#     -------
#     value_grpc : google.protobuf.internal.enum_type_wrapper.EnumTypeWrapper
#         gRPC value.
#     """

#     if type == AuthenticationMode:
#         return AUTH_MODE_PY_TO_GRPC[value_py]
#     if type == TimestampFormat:
#         return TIMESTAMP_FORMAT_PY_TO_GRPC[value_py]
#     if type == PacketLossType:
#         return PACKET_LOSS_TYPE_PY_TO_GRPC[value_py]
#     if type == DelayMeasurementMode:
#         return DELAY_MEASUREMENT_MODE_PY_TO_GRPC[value_py]
#     if type == SessionReflectorMode:
#         return SESSION_REFLECTOR_MODE_PY_TO_GRPC[value_py]
#     if type == StatusCode:
#         return STATUS_CODE_PY_TO_GRPC[value_py]


class STAMPTestResults:
    """
    A class to represent the results of a single STAMP Session.

    ...

    Attributes
    ----------
    ssid : int
        16-bit Session Segment Identifier (SSID).
    test_pkt_tx_timestamp : float
        STAMP Test packet transmission timestamp (taken on Sender)
    reply_pkt_tx_timestamp : float
        STAMP Test Reply packet transmission timestamp (taken on Reflector)
    reply_pkt_rx_timestamp : float
        STAMP Test Reply packet receive timestamp (taken on Sender)
    test_pkt_rx_timestamp : float
        STAMP Test packet receive timestamp (taken on Reflector)
    """

    def __init__(self, ssid, test_pkt_tx_timestamp, reply_pkt_tx_timestamp,
                 reply_pkt_rx_timestamp, test_pkt_rx_timestamp):
        """
        Constructs all the necessary attributes for the STAMP Test Results
        object.

        ssid : int
            16-bit Session Segment Identifier (SSID).
        test_pkt_tx_timestamp : float
            STAMP Test packet transmission timestamp (taken on Sender)
        reply_pkt_tx_timestamp : float
            STAMP Test Reply packet transmission timestamp (taken on Reflector)
        reply_pkt_rx_timestamp : float
            STAMP Test Reply packet receive timestamp (taken on Sender)
        test_pkt_rx_timestamp : float
            STAMP Test packet receive timestamp (taken on Reflector)
        """

        # 16-bit STAMP Session Identifier (SSID)
        self.ssid = ssid
        # STAMP Test packet transmission timestamp (taken on Sender)
        self.test_pkt_tx_timestamp = test_pkt_tx_timestamp
        # STAMP Test Reply packet transmission timestamp (taken on Reflector)
        self.reply_pkt_tx_timestamp = reply_pkt_tx_timestamp
        # STAMP Test Reply packet receive timestamp (taken on Sender)
        self.reply_pkt_rx_timestamp = reply_pkt_rx_timestamp
        # STAMP Test packet receive timestamp (taken on Reflector)
        self.test_pkt_rx_timestamp = test_pkt_rx_timestamp


class STAMPSession:
    """
    A class to represent a STAMP Session.

    ...

    Attributes
    ----------
    ssid : int
        16-bit Session Segment Identifier (SSID).
    auth_mode : utils.AuthenticationMode
        Authentication Mode (i.e. Authenticated or Unauthenticated).
    key_chain : str
        Key chain used for the Authenticated Mode.
    timestamp_format : utils.TimestampFormat
        Format of the timestamp (i.e. NTP or PTPv2).
    sequence_number : int
        An 32-bit integer that represents the STAMP Sequence Number.
    is_running : bool
        Define whether the STAMP Session is running or not.
    stamp_source_ipv4_address : str
        IP address to be used as source IPv4 address of the STAMP packets.
         If it is None, the global IPv4 address will be used as source
         IPv4 address.

    Methods
    -------
    set_started()
        Mark the STAMP Session as running.
    clear_started()
        Mark the STAMP Session as NOT running.
    """

    def __init__(self, ssid, auth_mode, key_chain, timestamp_format,
                 sender_ipv4_addr, reflector_ipv4_addr, 
                 sender_send_port, sender_rev_port, 
                 reflector_send_port, reflector_recv_port):
        """
        Constructs all the necessary attributes for the STAMP Session object.

        Parameters
        ----------
        ssid : int
            16-bit Session Segment Identifier (SSID).
        auth_mode : utils.AuthenticationMode
            Authentication Mode (i.e. Authenticated or Unauthenticated).
        key_chain : str
            Key chain used for the Authenticated Mode.
        timestamp_format : utils.TimestampFormat
            Format of the timestamp (i.e. NTP or PTPv2).
        stamp_source_ipv4_address : str, optional
            IP address to be used as source IPv4 address of the STAMP packets.
             If it is None, the global IPv4 address will be used as source
             IPv4 address (default: None).
        """

        # STAMP Session Identifier
        self.ssid = ssid
        # Authentication Mode (e.g. Unauthenticated or HMAC SHA 256)
        self.auth_mode = auth_mode
        # Key chain required for the Authenticated Mode
        self.key_chain = key_chain
        # Timestamp Format (i.e. NTP or PTPv2)
        self.timestamp_format = timestamp_format
        # Sequence Number
        self.sequence_number = 0
        # Flag set if the STAMP Session is running
        self.is_running = False
        # IP address of the sender
        self.sender_ipv4_addr = sender_ipv4_addr
        # IP address of the reflector
        self.reflector_ipv4_addr = reflector_ipv4_addr
        # Sender UDP sending port
        self.sender_send_port = sender_send_port
        # Sender UDP reciving port
        self.sender_rev_port = sender_rev_port
        # Reflector UDP sending port
        self.reflector_send_port = reflector_send_port
        # Reflector UDP reciving port
        self.reflector_recv_port = reflector_recv_port

        self.packet_template = None
        self.pseudo_header = None

    def set_started(self):
        """
        Mark the STAMP Session as running.

        Returns
        -------
        None.
        """

        logging.debug('Setting STAMP Session %d as running', self.ssid)
        self.is_running = True

    def clear_started(self):
        """
        Mark the STAMP Session as NOT running.

        Returns
        -------
        None.
        """

        logging.debug('Setting STAMP Session %d as NOT running', self.ssid)
        self.is_running = False


class STAMPSenderSession(STAMPSession):
    """
    A class to represent a STAMP Session of a STAMP Sender.

    ...

    Attributes
    ----------
    ssid : int
        16-bit Session Segment Identifier (SSID).
    reflector_ip : str
        IP address of the STAMP Session Reflector.
    reflector_udp_port : int
        UDP port of STAMP Session Reflector.
    sidlist : list
        Segment List for the direct SRv6 path (Sender -> Reflector).
    interval : int
        Interval (in seconds) between two STAMP packets.
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
    stop_flag : threading.Event
        A threading event used to stop the STAMP Session.
    test_results : queue.Queue()
        A queue to store the Test results for this STAMP Session.
    sequence_number : int
        An 32-bit integer that represents the STAMP Sequence Number.
    is_running : bool
        Define whether the STAMP Session is running or not.
    stamp_source_ipv4_address : str
        IP address to be used as source IPv4 address of the STAMP packets.
         If it is None, the global IPv4 address will be used as source
         IPv4 address.

    Methods
    -------
    add_test_results(test_pkt_tx_timestamp, reply_pkt_tx_timestamp,
                     reply_pkt_rx_timestamp, test_pkt_rx_timestamp)
        Add a new Test result to the STAMP Session.
    get_test_results(num=0)
        Get N STAMP Test results and remove them from the Session.
    """

    def __init__(self, ssid, reflector_ipv4_addr, reflector_udp_port, sender_udp_port,
                 interval, auth_mode, key_chain, timestamp_format,
                 packet_loss_type, delay_measurement_mode, stop_flag=None,
                 sender_ipv4_addr=None):
        """
        Constructs all the necessary attributes for the STAMP Session object.

        Parameters
        ----------
        ssid : int
            16-bit Session Segment Identifier (SSID).
        reflector_ip : str
            IP address of the STAMP Session Reflector.
        reflector_udp_port : int
            UDP port of STAMP Session Reflector.
        interval : int
            Interval (in seconds) between two STAMP packets.
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
        stop_flag : threading.Event
            A threading event used to stop the STAMP Session.
        stamp_source_ipv6_address : str, optional
            IP address to be used as source IPv6 address of the STAMP packets.
             If it is None, the global IPv6 address will be used as source
             IPv6 address (default: None).
        """

        # Initialize super class STAMPSession
        super().__init__(ssid, auth_mode, key_chain, timestamp_format,
                         sender_ipv4_addr, reflector_ipv4_addr, 
                         sender_udp_port, sender_udp_port, 
                         reflector_udp_port, reflector_udp_port)
        # Packet Loss Type (i.e. Round Trip, Near End, Far End)
        self.packet_loss_type = packet_loss_type
        # Delay Measurement Mode (i.e. One-Way, Two-Way or Loopback)
        self.delay_measurement_mode = delay_measurement_mode
        # Interval (in seconds) between two STAMP packets
        self.interval = interval
        # A queue to store the Test results for this STAMP Session
        self.test_results = queue.Queue()
        # Flag used to stop the STAMP Session
        self.stop_flag = stop_flag

    def add_test_results(self, test_pkt_tx_timestamp, reply_pkt_tx_timestamp,
                         reply_pkt_rx_timestamp, test_pkt_rx_timestamp):
        """
        Add a new Test result to the STAMP Session.

        Parameters
        ----------
        test_pkt_tx_timestamp : float
            STAMP Test packet transmission timestamp (taken on Sender)
        reply_pkt_tx_timestamp : float
            STAMP Test Reply packet transmission timestamp (taken on Reflector)
        reply_pkt_rx_timestamp : float
            STAMP Test Reply packet receive timestamp (taken on Sender)
        test_pkt_rx_timestamp : float
            STAMP Test packet receive timestamp (taken on Reflector)

        Returns
        -------
        None.
        """

        logging.debug('Adding new STAMP Test results to STAMP session, '
                      '(SSID %d): '
                      'test_pkt_tx_timestamp: %d, '
                      'reply_pkt_tx_timestamp: %d, '
                      'reply_pkt_rx_timestamp: %d, '
                      'test_pkt_rx_timestamp: %d',
                      self.ssid,
                      test_pkt_tx_timestamp,
                      reply_pkt_tx_timestamp,
                      reply_pkt_rx_timestamp,
                      test_pkt_rx_timestamp
                      )

        # Build an instance of STAMPTestResults
        stamp_test_result = STAMPTestResults(
            ssid=self.ssid,
            test_pkt_tx_timestamp=test_pkt_tx_timestamp,
            reply_pkt_tx_timestamp=reply_pkt_tx_timestamp,
            reply_pkt_rx_timestamp=reply_pkt_rx_timestamp,
            test_pkt_rx_timestamp=test_pkt_rx_timestamp
        )

        # Enqueue results to the current STAMP Session
        self.test_results.put(stamp_test_result)

        logging.debug('STAMP Test Results added')

    def get_test_results(self, num=0):
        """
        Get N STAMP Test results and remove them from the Session.

        Parameters
        ----------
        num : int, optional
            The number of test results to be returned. If num is 0 or a
            negative number, all the results are returned (default is 0)

        Returns
        -------
        A list of STAMP Test Results. The list may contain fewer items than
         required, if less elements are available.
        """

        logging.debug('Get Test results for STAMP Session (SSID %d)',
                      self.ssid)

        # Initialize a list to store the results to be returned
        results = list()

        # If num is 0 or a negative number, we want to return all the results
        get_all_results = True if num <= 0 else False

        # Iterate on the test_results queue and get the results
        while get_all_results is True or num > 0:
            try:
                # Remove an item from the queue
                stamp_result = self.test_results.get_nowait()
                # Logging
                logging.debug('Got STAMP Result for STAMP Session (SSID %d): '
                              'test_pkt_tx_timestamp: %d, '
                              'reply_pkt_tx_timestamp: %d, '
                              'reply_pkt_rx_timestamp: %d, '
                              'test_pkt_rx_timestamp: %d',
                              self.ssid,
                              stamp_result.test_pkt_tx_timestamp,
                              stamp_result.reply_pkt_tx_timestamp,
                              stamp_result.reply_pkt_rx_timestamp,
                              stamp_result.test_pkt_rx_timestamp)
                # Append the item to the results list
                results.append(stamp_result)
                # Decrease the number of results to be returned
                num -= 1
            except queue.Empty:
                # We reached the end of the queue, stop the "while" loop
                break

        logging.debug('Returned %d STAMP Results', len(results))

        # Return the results
        return results


class STAMPReflectorSession(STAMPSession):
    """
    A class to represent a STAMP Session of a STAMP Reflector.

    ...

    Attributes
    ----------
    ssid : int
        16-bit Session Segment Identifier (SSID).
    reflector_udp_port : int
        UDP port of STAMP Session Reflector.
    auth_mode : utils.AuthenticationMode
        Authentication Mode (i.e. Authenticated or Unauthenticated).
    key_chain : str
        Key chain used for the Authenticated Mode.
    timestamp_format : utils.TimestampFormat
        Format of the timestamp (i.e. NTP or PTPv2).
    session_reflector_mode : utils.SessionReflectorMode
        Mode used by the STAMP Reflector (i.e. Stateless or Stateful).
    sequence_number : int
        An 32-bit integer that represents the STAMP Sequence Number.
    is_running : bool
        Define whether the STAMP Session is running or not.
    stamp_source_ipv6_address : str
        IP address to be used as source IPv6 address of the STAMP packets.
         If it is None, the global IPv6 address will be used as source
         IPv6 address.

    Methods
    -------
    """

    def __init__(self, ssid, reflector_udp_port,
                 auth_mode, key_chain, timestamp_format, session_reflector_mode,
                 stamp_source_ipv4_address=None):
        """
        Constructs all the necessary attributes for the STAMP Session object.

        Parameters
        ----------
        ssid : int
            16-bit Session Segment Identifier (SSID).
        reflector_udp_port : int
            UDP port of STAMP Session Reflector.
        auth_mode : utils.AuthenticationMode
            Authentication Mode (i.e. Authenticated or Unauthenticated).
        key_chain : str
            Key chain used for the Authenticated Mode.
        timestamp_format : utils.TimestampFormat
            Format of the timestamp (i.e. NTP or PTPv2).
        session_reflector_mode : utils.SessionReflectorMode
            Mode used by the STAMP Reflector (i.e. Stateless or Stateful).
        stamp_source_ipv4_address : str, optional
            IP address to be used as source IPv4 address of the STAMP packets.
             If it is None, the global IPv4 address will be used as source
             IPv4 address (default: None).
        """

        # Initialize super class STAMP Session
        super().__init__(ssid, auth_mode, key_chain, timestamp_format, 
                         None, stamp_source_ipv4_address, 
                         None, None, 
                         reflector_udp_port, reflector_udp_port 
                         )
        # UDP port of the STAMP Session Reflector
        self.reflector_udp_port = reflector_udp_port
        # Mode used by the STAMP Reflector (i.e. Stateless or Stateful)
        self.session_reflector_mode = session_reflector_mode


def validate_ipv6_address(ip):
    """
    Utility function to check if the IP is a valid IPv6 address.

    Parameters
    ----------
    ip : str
        The IP address to validate.

    Returns
    -------
    is_valid : bool
        True if the IP is a valid IPv6 address, False otherwise.
    """

    if ip is None:
        return False
    try:
        IPv6Interface(ip)
        return True
    except AddressValueError:
        return False


def validate_ipv4_address(ip):
    """
    Utility function to check if the IP is a valid IPv4 address.

    Parameters
    ----------
    ip : str
        The IP address to validate.

    Returns
    -------
    is_valid : bool
        True if the IP is a valid IPv4 address, False otherwise.
    """

    if ip is None:
        return False
    try:
        IPv4Interface(ip)
        return True
    except AddressValueError:
        return False


def validate_ip_address(ip):
    """
    Utility function to check if the IP is a valid address.

    Parameters
    ----------
    ip : str
        The IP address to validate.

    Returns
    -------
    is_valid : bool
        True if the IP is a valid IP address, False otherwise.
    """

    return validate_ipv4_address(ip) or validate_ipv6_address(ip)


def get_address_family(ip):
    """
    Utility function to get the IP address family.

    Parameters
    ----------
    ip : str
        The IP address to validate.

    Returns
    -------
    family : bool
        AF_INET if the IP is an IPv4 address, AF_INET6 if the IP is an IPv6
        address, None if the IP address is invalid.
    """

    if validate_ipv6_address(ip):
        # IPv6 address
        return AF_INET6
    elif validate_ipv4_address(ip):
        # IPv4 address
        return AF_INET
    else:
        # Invalid address
        return None
