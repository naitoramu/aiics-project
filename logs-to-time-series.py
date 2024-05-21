import pandas as pd
from LogParser import LogParser

dtype_dict = {
    'arp.dst.proto_ipv4': 'str',
    'arp.src.proto_ipv4': 'str',
    'dns.qry.name': 'str',  # Assuming these are the columns with mixed types
    'dns.qry.type': 'str',
}
filepaths = [
    '../normal-traffic.csv',
    '../port-scanning.csv',
    '../ddos-tcp-syn-flood.csv',
]

for filepath in filepaths:
    df = pd.read_csv(filepath, parse_dates=['frame.time'], dtype=dtype_dict, low_memory=False)

    logs_series = LogParser.logs_to_series(df, 64);

    print(len(logs_series))
    print(logs_series[0])