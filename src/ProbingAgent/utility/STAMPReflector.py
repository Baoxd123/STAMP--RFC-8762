import logging
from concurrent import futures
import time
import argparse

from ..STAMPReflector import STAMPSessionReflector
from ..utils_ipv4 import (AuthenticationMode, 
                        DelayMeasurementMode, 
                        PacketLossType, 
                        SessionReflectorMode, 
                        TimestampFormat)


# Get the root logger
logger = logging.getLogger()

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reflector_iface", required=True, type=str, help="Network interface of the receiving STAMP packets")
    parser.add_argument("--reflector_ip", required=True, type=str, help="IPv4 address of reflector")
    parser.add_argument("--reflector_port", type=int, default=862, help="Reflector UDP port, default 862")
    
    parser.add_argument("--num_flows", type=int, default=10, help="Number of flows, default 10 flows")
    parser.add_argument("--duration", type=int, default=-1, help="Duration of the probing in seconds or -1 to run indefinitely, default -1")

    args = parser.parse_args()
    return args

def main():
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
        print('\nCTRL+C caught. Graceful stopping...')

    for i in range(args.num_flows):
        reflector.stop_stamp_session(ssid=i)
        reflector.destroy_stamp_session(ssid=i)
    
    reflector.reset()


if __name__ == "__main__":
    main()
    
