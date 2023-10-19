import typing
import pandas as pd


def parse_raw_data_to_pandas(raw_data):
    """Save the probing data into csv.
        Input is a list of list of data. 
        Data points is a dictionary with the following keys
            ssid
            test_pkt_tx_timestamp
            reply_pkt_tx_timestamp
            reply_pkt_rx_timestamp
            test_pkt_rx_timestamp
        
        Output format:
        ssid | test_pkt_tx_timestamp | test_pkt_rx_timestamp | reply_pkt_tx_timestamp | reply_pkt_rx_timestamp

    Args:
        raw_data (list[list[dict]]): test result structured as above
        file_path (str): path to save the file

    Returns:
        pandas.DataFrame: output of the parsed data
    """
    # merge list
    data = []
    for flow in raw_data:
        data += flow
    
    # Convert into pandas data frame
    data_df = pd.DataFrame(data)
    data_df = data_df.reindex(columns=["ssid", "test_pkt_tx_timestamp", "test_pkt_rx_timestamp", "reply_pkt_tx_timestamp", "reply_pkt_rx_timestamp"])
    
    # Sort by test_pkt_tx_timestamp
    data_df.sort_values(by=['test_pkt_tx_timestamp'], inplace=True)
    data_df.reset_index(drop=True, inplace=True)

    return data_df

def parse_rtt_by_flow(data, sampling_rate):
    # calculate rtt
    data["rtt_s"] = (data["reply_pkt_rx_timestamp"] - data["test_pkt_tx_timestamp"])

    # Calculate time window
    min_timestamp = data["test_pkt_tx_timestamp"].min()
    data["Time"] = ((data["test_pkt_tx_timestamp"] - min_timestamp) // sampling_rate) * sampling_rate
    
    # Get session IDs
    ssids = data["ssid"].unique()

    # Calculate average per flow
    res_df = data[["Time", "rtt_s"]]
    res_df = res_df.groupby(res_df['Time']).mean().reset_index()

    for ssid in ssids:
        temp_df = data.loc[data['ssid'] == ssid][["Time", "rtt_s"]]
        res_df[ssid] = temp_df.groupby(temp_df['Time']).mean()
    
    res_df = res_df.rename(columns={"rtt_s": "Aggregate-Flow"})
    
    return res_df
