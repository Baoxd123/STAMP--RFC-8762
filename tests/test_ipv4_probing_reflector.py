import sys
import logging
import grpc
from concurrent import futures
import unittest
import time

from ProbingAgent.STAMPReflector import STAMPSessionReflector
from ProbingAgent.utils_ipv4 import (AuthenticationMode, 
                        DelayMeasurementMode, 
                        PacketLossType, 
                        SessionReflectorMode, 
                        TimestampFormat)


# Get the root logger
logger = logging.getLogger()


SENDER_GRPC_PORT = None
RAMDON_SENDER_UDP_PORT = 0
REFLECTOR_INTERFACE = ["ens160"]
REFLECTOR_GRPC_PORT = 12345
SENDER_IP= "128.238.147.69"
REFLECTOR_IP = "128.238.147.71"
SSID = 1
REFLECTOR_UPD_PORT = 862

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig()
    # logging.getLogger().setLevel(logging.DEBUG)

    # Create a STAMP Session Reflector object
    reflector = STAMPSessionReflector()

    reflector.init(
        reflector_udp_port=REFLECTOR_UPD_PORT,
        interfaces=REFLECTOR_INTERFACE,
        stamp_source_ipv4_address=REFLECTOR_IP
    )

    # Create STAMP Session
    reflector.create_stamp_session(
    ssid=SSID,
    stamp_source_ipv4_address=REFLECTOR_IP,
    auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
    key_chain=None,
    timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
    session_reflector_mode=SessionReflectorMode.SESSION_REFLECTOR_MODE_STATELESS.value,
    reflector_udp_port=REFLECTOR_UPD_PORT
    )

    reflector.create_stamp_session(
    ssid=2,
    stamp_source_ipv4_address=REFLECTOR_IP,
    auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
    key_chain=None,
    timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
    session_reflector_mode=SessionReflectorMode.SESSION_REFLECTOR_MODE_STATELESS.value,
    reflector_udp_port=REFLECTOR_UPD_PORT
    )

    # Start STAMP Session
    reflector.start_stamp_session(SSID)
    reflector.start_stamp_session(2)

    try:
        # print('sleep 60')
        # time.sleep(60)
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print('CTRL+C catched. Graceful stopping...')

    reflector.stop_stamp_session(ssid=SSID)
    reflector.stop_stamp_session(ssid=2)

    reflector.destroy_stamp_session(ssid=SSID)
    reflector.destroy_stamp_session(ssid=2)
    
    reflector.reset()

