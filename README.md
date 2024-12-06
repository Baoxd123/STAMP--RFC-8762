# STAMP
A network measurement tool based on STAMP, Simple Two-Way Active Measurement Protocol (RFC 8762). 
## Download and Installation
`pip install git+https://github.com/Baoxd123/STAMP--RFC-8762.git`
## Quick Start
Launch the STAMPReflector ready to receive up to 10 flows:
```
STAMPReflector --reflector_iface <RECEIVER_INTERFACE> --reflector_ip <RECEIVER_IP>
```
Launch STAMPSender on your sender machine sending 10 flows with a probing rate of 10 pps for 60 seconds to your reflector at RECEIVER_IP.
```
STAMPSender --exp_name test_experiment --sender_ip <SENDER_IP> --sender_iface <SENDER_INTERFACE> --reflector_ip <RECEIVER_IP>
```

## STAMPReflector
### Command Line Options
| Command | Description |
| --- | --- |
| `--reflector_ip <IP_ADDRESS>` | IPv4 address of reflector. |
| `--reflector_iface <NETWORK_INTERFACE>` | Network interface for receiving STAMP packets. |
| `--reflector_port <SOURCE_PORT>` | Reflector UDP port (default 862). |
| `--num_flows <NUMBER_OF_FLOWS>` | Number of flows (default 10 flows).
| `--duration <SECONDS>` | Duration of the probing in seconds or -1 to run indefinitely (default -1). |


## STAMPSender
### Command Line Options
| Command | Description |
| --- | --- |
| `--exp_name <EXP_NAME>` | Name of the experiment. This argument is also use for the name of the output files |
| `--save_dir <DIRECTORY>` | Directory path to save the probing result (default is the current directory). |
| `--sender_ip <IP_ADDRESS>` | IPv4 address of sender. |
| `--sender_iface [NETWORK_INTERFACE ...]` | List of network interface of the sender. |
| `--reflector_ip <IP_ADDRESS>` | IPv4 address of reflector for receiving the probing packets. |
| `--reflector_port <DESTINATION_PORT>` | Reflector UDP port (default 862).|
| `--saving_period <SECOND>` | The number of seconds for the system to save the data to disk to free up RAM space. (Default = 1 seconds) |
|||
| `--src_ports [SRC_PORTS ...]` | List of source ports used to send STAMP packets. |
| `--num_flows <NUMBER_OF_FLOWS>` | Number of flows. (Default 10) |
| `--duration <SECONDS>` | Duration of the probing in seconds. (Default 60 seconds) |
| `--rate <RATE>` | Probing rate in pkts/s. (Default 10 pkts/s) |
| `--set_seed <SEED>` | Set seed for random functions. (Default = 0) |

## Output File Structure

### Flow Information: EXP_NAME_flow_info.csv
This file contains the experiment parameter of each flow.
| ssid | src_ip | dst_ip | src_port | dst_port | interval |
| --- | --- | --- | --- | --- | --- |
| ... | ... | ... | ... | ... | ... |

### Raw Data: EXP_NAME_raw.csv
This file contains the packet level raw data. 
| ssid | test_pkt_tx_timestamp | test_pkt_rx_timestamp | reply_pkt_tx_timestamp | reply_pkt_rx_timestamp |
| --- | --- | --- | --- | --- |
| ... | ... | ... | ... | ... |
### RTT Data: EXP_NAME_rtt.dat
This file contains the parsed RTT data of each flow. Aggregate-Flow column represents the average RTT of all flow. 
| Time | Aggregate-Flow | flow_id_1 | ... | flow_id_n |
| --- | --- | --- | --- | --- |
| ... | ... | ... | ... | ... |
