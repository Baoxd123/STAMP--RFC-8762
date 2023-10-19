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
# Python Library implementing the STAMP protocol [RFC8762].
#
# @author Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#


"""Python Library implementing the STAMP protocol [RFC8762]."""

from ProbingAgent.stamp.core_ipv4 import (
    SEQUENCE_NUMBER_OFFSET,
    SEQUENCE_NUMBER_LENGTH,
    TIMESTAMP_OFFSET,
    TIMESTAMP_LENGTH,
    ERROR_ESTIMATE_OFFSET,
    ERROR_ESTIMATE_LENGTH,
    SSID_OFFSET,
    SSID_LENGTH,
    RECEIVE_TIMESTAMP_OFFSET,
    RECEIVE_TIMESTAMP_LENGTH,
    SENDER_INFORMATION_OFFSET,
    SENDER_INFORMATION_LENGTH,
    UDP_CHECKSUM_OFFSET,
    UDP_CHECKSUM_LENGTH,
    DST_UDP_PORT_OFFSET,
    DST_UDP_PORT_LENGTH,
    SRC_UDP_PORT_OFFSET,
    SRC_UDP_PORT_LENGTH,
    STAMP_PACKET_LENGTH,
    Timestamp,
    ParsedSTAMPTestPacket,
    ParsedSTAMPTestReplyPacket,
    STAMPTestPacket,
    STAMPReplyPacket,
    AuthenticationMode,
    TimestampFormat,
    PacketLossType,
    DelayMeasurementMode,
    SessionReflectorMode,
    TimestampFormatFlag,
    SyncFlag,
    get_timestamp_unix,
    get_timestamp_ntp,
    get_timestamp_ptp,
    ntp_to_unix_timestamp,
    ptp_to_unix_timestamp,
    generate_stamp_test_packet,
    generate_stamp_reply_packet,
    generate_stamp_test_reply_packet,
    parse_stamp_test_packet,
    parse_stamp_reply_packet,
    send_stamp_packet,
    get_stamp_test_reply_template
)

__all__ = [
    "SEQUENCE_NUMBER_OFFSET",
    "SEQUENCE_NUMBER_LENGTH",
    "TIMESTAMP_OFFSET",
    "TIMESTAMP_LENGTH",
    "ERROR_ESTIMATE_OFFSET",
    "ERROR_ESTIMATE_LENGTH",
    "SSID_OFFSET",
    "SSID_LENGTH",
    "RECEIVE_TIMESTAMP_OFFSET",
    "RECEIVE_TIMESTAMP_LENGTH",
    "SENDER_INFORMATION_OFFSET",
    "SENDER_INFORMATION_LENGTH",
    "UDP_CHECKSUM_OFFSET",
    "UDP_CHECKSUM_LENGTH",
    "DST_UDP_PORT_OFFSET",
    "DST_UDP_PORT_LENGTH",
    "SRC_UDP_PORT_OFFSET",
    "SRC_UDP_PORT_LENGTH",
    "STAMP_PACKET_LENGTH",
    'Timestamp',
    'ParsedSTAMPTestPacket',
    'ParsedSTAMPTestReplyPacket',
    'STAMPTestPacket',
    'STAMPReplyPacket',
    'AuthenticationMode',
    'TimestampFormat',
    'PacketLossType',
    'DelayMeasurementMode',
    'SessionReflectorMode',
    'TimestampFormatFlag',
    'SyncFlag',
    'get_timestamp_unix',
    'get_timestamp_ntp',
    'get_timestamp_ptp',
    'ntp_to_unix_timestamp',
    'ptp_to_unix_timestamp',
    'generate_stamp_test_packet',
    'generate_stamp_reply_packet',
    "generate_stamp_test_reply_packet",
    'parse_stamp_test_packet',
    'parse_stamp_reply_packet',
    'send_stamp_packet',
    "get_stamp_test_reply_template"
]
