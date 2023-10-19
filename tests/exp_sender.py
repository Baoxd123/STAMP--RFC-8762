import sys
import logging
import grpc
from concurrent import futures
import time
import argparse
import pandas as pd
import numpy as np

from ProbingAgent.STAMPSender import STAMPSessionSender
from ProbingAgent.utils_ipv4 import (AuthenticationMode, 
                        DelayMeasurementMode, 
                        PacketLossType, 
                        SessionReflectorMode, 
                        TimestampFormat)

from ProbingAgent.utility.save_probing_data import parse_raw_data_to_pandas, parse_rtt_by_flow

# Get the root logger
logger = logging.getLogger()

def append_results_to_csv(sender, num_flow, fname):
    # Quary results
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
    parser.add_argument("--file_path", type=str, required=True, help="Path to save the probing result")
    parser.add_argument("--sender_ip", type=str, default="128.238.147.69", help="IPv4 address of sender")
    parser.add_argument("--sender_iface", type=str, nargs='+', default=["ens160"], help="Network interface of the sender")
    parser.add_argument("--reflector_ip", type=str, default="128.238.147.71", help="IPv4 address of reflector")
    parser.add_argument("--reflector_port", type=int, default=862, help="Reflector UDP port")
    
    parser.add_argument("--num_flows", type=int, default=10, help="Number of flows")
    parser.add_argument("--duration", type=int, default=60, help="Duradion of the probing in seconds")
    parser.add_argument("--rate", type=int, default=10, help="Probing rage in pkts/s")

    parser.add_argument("--saving_peroid", type=int, default=600, help="The number of seconds for the systme to save the data to disk to free up RAM space. Default = 10 min")
    parser.add_argument("--set_seed", type=int, default=0, help="set seed for random functions")


    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_arguments()

    # Configure logging
    logging.basicConfig()
    # logging.getLogger().setLevel(logging.DEBUG)

    # Create CSV file for saving data
    headers = {
        "ssid": [],
        "test_pkt_tx_timestamp": [],
        "test_pkt_rx_timestamp": [],
        "reply_pkt_tx_timestamp": [],
        "reply_pkt_rx_timestamp": [],
        
    }
    df_haders = pd.DataFrame(headers)
    df_haders.to_csv(args.file_path + "_raw.csv", index=False)

    # Generate sorce port numbers
    src_prots = gen_src_ports(args.num_flows, args.set_seed)

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
            sender_udp_port=src_prots[i]
        )

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
    flow_info_df.to_csv(args.file_path + "_flow_info.csv", index=False)

    # Start all sessions
    [sender.start_stamp_session(i, only_collector=False) for i in range(args.num_flows)]

    # Wait
    end_time = time.perf_counter() + args.duration
    remaining_time = end_time - time.perf_counter()
    try:
        while remaining_time > args.saving_peroid:
            time.sleep(args.saving_peroid)
            # Appending current data to disk to free up RAM space
            append_results_to_csv(sender, args.num_flows, args.file_path + "_raw.csv")
            remaining_time = end_time - time.perf_counter()
        time.sleep(remaining_time)
    except KeyboardInterrupt:
        print('CTRL+C catched. Graceful stopping...')

    # Stop all session
    [sender.stop_stamp_session(ssid=i) for i in range(args.num_flows)]

    # Save raw data to CSV
    append_results_to_csv(sender, args.num_flows, args.file_path + "_raw.csv")

    # Parse RTT from raw data
    raw_data_df = pd.read_csv(args.file_path + "_raw.csv")
    rtt_data_df = parse_rtt_by_flow(raw_data_df, 1)
    rtt_data_df.to_csv(args.file_path + "_rtt.csv", index=False)

    # Close all STAMP session
    [sender.destroy_stamp_session(ssid=i) for i in range(args.num_flows)]
    sender.reset()

