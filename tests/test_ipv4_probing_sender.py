import sys
import logging
import grpc
from concurrent import futures
import unittest
import time

from ProbingAgent.STAMPSender import STAMPSessionSender
from ProbingAgent.utils_ipv4 import (AuthenticationMode, 
                        DelayMeasurementMode, 
                        PacketLossType, 
                        SessionReflectorMode, 
                        TimestampFormat)

# Get the root logger
logger = logging.getLogger()


SENDER_GRPC_PORT = None
RAMDON_SENDER_UDP_PORT = 0
SENDER_INTERFACE = ["ens160"]
REFLECTOR_GRPC_PORT = 12345
SENDER_IP= "128.238.147.69"
REFLECTOR_IP = "128.238.147.71"
SSID = 1
REFLECTOR_UPD_PORT = 862


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig()
    # logging.getLogger().setLevel(logging.DEBUG)

    # Create a STAMP Session Sender object
    sender = STAMPSessionSender()
    sender.init(
        sender_udp_port=RAMDON_SENDER_UDP_PORT,
        interfaces=SENDER_INTERFACE, 
        stamp_source_ipv4_address=SENDER_IP
    )
    sender.create_stamp_session(
        ssid=SSID, 
        reflector_ip=REFLECTOR_IP,
        stamp_source_ipv4_address=SENDER_IP,
        interval=3,
        auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
        key_chain=None,
        timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
        packet_loss_type=PacketLossType.PACKET_LOSS_TYPE_ROUND_TRIP,
        delay_measurement_mode=DelayMeasurementMode.DELAY_MEASUREMENT_MODE_TWO_WAY,
        reflector_udp_port=REFLECTOR_UPD_PORT, 
        sender_udp_port=0
    )

    sender.create_stamp_session(
        ssid=2, 
        reflector_ip=REFLECTOR_IP,
        stamp_source_ipv4_address=SENDER_IP,
        interval=3,
        auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
        key_chain=None,
        timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
        packet_loss_type=PacketLossType.PACKET_LOSS_TYPE_ROUND_TRIP,
        delay_measurement_mode=DelayMeasurementMode.DELAY_MEASUREMENT_MODE_TWO_WAY,
        reflector_udp_port=REFLECTOR_UPD_PORT, 
        sender_udp_port=0
    )

    sender.start_stamp_session(SSID, only_collector=False)
    sender.start_stamp_session(2, only_collector=False)

    time.sleep(10)

    sender.stop_stamp_session(ssid=SSID)
    sender.stop_stamp_session(ssid=2)

    results = sender.get_stamp_session_results(SSID)
    [print(res) for res in results]

    results = sender.get_stamp_session_results(2)
    [print(res) for res in results]
    
    
    sender.destroy_stamp_session(ssid=SSID)
    sender.destroy_stamp_session(ssid=2)
    
    sender.reset()

    

