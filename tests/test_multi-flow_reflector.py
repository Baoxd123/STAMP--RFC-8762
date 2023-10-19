import sys
import logging
import grpc
from concurrent import futures
import unittest
import time
import argparse

from ProbingAgent.STAMPReflector import STAMPSessionReflector
from ProbingAgent.utils_ipv4 import (AuthenticationMode, 
                        DelayMeasurementMode, 
                        PacketLossType, 
                        SessionReflectorMode, 
                        TimestampFormat)


# Get the root logger
logger = logging.getLogger()

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reflector_iface", type=str, default="ens160", help="Network interface of the sender")
    parser.add_argument("--reflector_ip", type=str, default="128.238.147.71", help="IPv4 address of reflector")
    parser.add_argument("--reflector_port", type=int, default=862, help="Reflector UDP port")
    
    parser.add_argument("--num_flows", type=int, default=10, help="Number of flows")
    parser.add_argument("--duration", type=int, default=-1, help="Duradion of the probing in seconds")

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_arguments()
    
    # Configure logging
    logging.basicConfig()
    # logging.getLogger().setLevel(logging.DEBUG)

    # Create a STAMP Session Reflector object
    reflector = STAMPSessionReflector()

    reflector.init(
        reflector_udp_port=args.reflector_port,
        interfaces=args.reflector_iface,
        stamp_source_ipv4_address=args.reflector_ip
    )

    # Create & start STAMP Session
    for i in range(args.num_flows):
        reflector.create_stamp_session(
        ssid=i,
        stamp_source_ipv4_address=args.reflector_ip,
        auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
        key_chain=None,
        timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
        session_reflector_mode=SessionReflectorMode.SESSION_REFLECTOR_MODE_STATELESS.value,
        reflector_udp_port=args.reflector_port
        )
        reflector.start_stamp_session(i)

    try:
        if args.duration != -1:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(65535)
    except KeyboardInterrupt:
        print('CTRL+C catched. Graceful stopping...')

    for i in range(args.num_flows):
        reflector.stop_stamp_session(ssid=i)
        reflector.destroy_stamp_session(ssid=i)
    
    reflector.reset()
    
