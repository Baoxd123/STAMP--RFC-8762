import logging
from concurrent import futures
import time
import argparse
import pandas as pd
import numpy as np
import os

from ..STAMPSender import STAMPSessionSender
from ..utils_ipv4 import (AuthenticationMode, 
                        DelayMeasurementMode, 
                        PacketLossType, 
                        SessionReflectorMode, 
                        TimestampFormat)

from ..utility.save_probing_data import parse_raw_data_to_pandas, parse_rtt_by_flow

# Get the root logger
logger = logging.getLogger()

def append_results_to_csv(sender, num_flow, fname):
    # Query results
    res = [sender.get_stamp_session_results(i) for i in range(num_flow)]
    # Convert to pandas data frame
    df = parse_raw_data_to_pandas(res)
    # Append to the CSV file
    df.to_csv(fname, mode="a", index=False, header=False)

def gen_src_ports(num_ports, seed):
    np.random.seed(seed)
    ports = np.random.choice(np.arange(49152, 65536), num_ports, replace=False)
    return ports

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exp_name", required=True, type=str, help="Name of the experiment")
    parser.add_argument("--save_dir", type=str, default="./", help="Directory path to save the probing result")
    parser.add_argument("--sender_ip", required=True, type=str, help="IPv4 address of sender")
    parser.add_argument("--sender_iface", required=True, type=str, nargs='+', help="Network interface of the sender")
    parser.add_argument("--reflector_ip", required=True, type=str, help="IPv4 address of reflector")
    parser.add_argument("--reflector_port", type=int, default=862, help="Reflector UDP port")
    
    parser.add_argument("--src_ports", type=int, nargs='+', default=[], help="Source ports used to send STAMP packets")
    parser.add_argument("--num_flows", type=int, default=10, help="Number of flows")
    
    parser.add_argument("--duration", type=int, default=60, help="Duration of the probing in seconds")
    parser.add_argument("--rate", type=int, default=10, help="Probing rate in pkts/s")

    parser.add_argument("--saving_period", type=int, default=1, help="The number of seconds for the system to save the data to disk to free up RAM space. Default = 1 seconds")
    parser.add_argument("--set_seed", type=int, default=0, help="set seed for random functions")


    args = parser.parse_args()
    return args


def main():
    args = parse_arguments()

    # Configure logging
    logging.basicConfig()
    # logging.getLogger().setLevel(logging.DEBUG)

    # Parse arguments
    if len(args.src_ports) == 0:
        # Generate source port numbers
        args.src_ports = gen_src_ports(args.num_flows, args.set_seed)
    else:
        args.num_flows = len(args.src_ports)

    flow_info_filename = os.path.join(args.save_dir, args.exp_name + "_flow_info.csv")
    raw_data_filename = os.path.join(args.save_dir, args.exp_name + "_raw.csv")
    rtt_data_filename = os.path.join(args.save_dir, args.exp_name + "_rtt.dat")


    # Create CSV file for saving data
    headers = {
        "ssid": [],
        "test_pkt_tx_timestamp": [],
        "test_pkt_rx_timestamp": [],
        "reply_pkt_tx_timestamp": [],
        "reply_pkt_rx_timestamp": [],
        
    }
    df_headers = pd.DataFrame(headers)
    df_headers.to_csv(raw_data_filename, index=False)


    # Create a STAMP Session Sender object
    sender = STAMPSessionSender()
    sender.init(
        reflector_udp_port=args.reflector_port,
        interfaces=args.sender_iface, 
        stamp_source_ipv4_address=args.sender_ip, 
    )

    # Create ans start STAMP sessions 
    for i in range(args.num_flows):
        sender.create_stamp_session(
            ssid=i, 
            reflector_ip=args.reflector_ip,
            stamp_source_ipv4_address=args.sender_ip,
            interval=1/args.rate,
            auth_mode=AuthenticationMode.AUTHENTICATION_MODE_UNAUTHENTICATED.value,
            key_chain=None,
            timestamp_format=TimestampFormat.TIMESTAMP_FORMAT_NTP.value,
            packet_loss_type=PacketLossType.PACKET_LOSS_TYPE_ROUND_TRIP,
            delay_measurement_mode=DelayMeasurementMode.DELAY_MEASUREMENT_MODE_TWO_WAY,
            reflector_udp_port=args.reflector_port, 
            sender_udp_port=args.src_ports[i]
        )

    # Start all sessions
    [sender.start_stamp_session(i, only_collector=False) for i in range(args.num_flows)]

    # Wait
    end_time = time.perf_counter() + args.duration
    remaining_time = end_time - time.perf_counter()
    try:
        while remaining_time > args.saving_period:
            time.sleep(args.saving_period)
            # Appending current data to disk to free up RAM space
            append_results_to_csv(sender, args.num_flows, raw_data_filename)
            remaining_time = end_time - time.perf_counter()
        time.sleep(remaining_time)
    except KeyboardInterrupt:
        print('\nCTRL+C caught. Graceful stopping...')

    # Stop all session
    [sender.stop_stamp_session(ssid=i) for i in range(args.num_flows)]

    # Save raw data to CSV
    append_results_to_csv(sender, args.num_flows, raw_data_filename)


    # save flow info
    flow_info = {
        "ssid": [],
        "src_ip": [],
        "dst_ip": [],
        "src_port": [],
        "dst_port": [], 
        "interval": []
    }
    for i in range(args.num_flows):
        flow_info["ssid"].append(i)
        flow_info["src_ip"].append(sender.stamp_sessions[i].sender_ipv4_addr)
        flow_info["dst_ip"].append(sender.stamp_sessions[i].reflector_ipv4_addr)
        flow_info["src_port"].append(sender.stamp_sessions[i].sender_send_port)
        flow_info["dst_port"].append(sender.stamp_sessions[i].reflector_recv_port)
        flow_info["interval"].append(sender.stamp_sessions[i].interval)
    flow_info_df = pd.DataFrame(flow_info)
    flow_info_df.to_csv(flow_info_filename, index=False)

    # Parse RTT from raw data
    raw_data_df = pd.read_csv(raw_data_filename)
    rtt_data_df = parse_rtt_by_flow(raw_data_df, 1)
    rtt_data_df.to_csv(rtt_data_filename, index=False, sep=" ")

    # Close all STAMP session
    [sender.destroy_stamp_session(ssid=i) for i in range(args.num_flows)]
    sender.reset()


if __name__ == "__main__":
    main()

