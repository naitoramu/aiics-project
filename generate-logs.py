import pandas as pd
from datetime import datetime, timedelta
import random


def random_date(start, end):
    return start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))


start_date = datetime(2024, 5, 13, 16, 0, 0)
end_date = datetime(2024, 5, 13, 19, 2, 37)


def generate_sample(traffic_type):
    frame_time = random_date(start_date, end_date).strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    if traffic_type == "Normal":
        ip_src_host = random.randint(0, 10)
        ip_dst_host = random.randint(0, 10)
        tcp_connection_syn = random.choice([0.0, 1.0])
        tcp_connection_synack = random.choice([0.0, 1.0])
        tcp_dstport = random.uniform(0, 7000)
        tcp_len = random.uniform(0, 1500)
        tcp_seq = random.uniform(0, 500000)
        tcp_flags_index = 4.0 if tcp_connection_syn == 1.0 else random.choice([0, 1, 2, 3, 5, 6, 7])
    elif traffic_type == "DDoS_TCP":
        tcp_dstport = random.uniform(1000, 70000)
        ip_src_host = random.randint(50000, 300000)
        ip_dst_host = random.randint(50000, 300000)
        tcp_connection_syn = random.choice([0.0, 1.0])
        tcp_connection_synack = random.choice([0.0, 1.0])
        tcp_len = random.choice([0.0, 120.0])
        tcp_seq = random.choice([0.0, 1.0])
        if tcp_dstport == 80.0:
            tcp_len = 120.0
            tcp_flags_index = 0.0
        else:
            tcp_len = random.choice([0.0, 120.0])
            tcp_flags_index = random.choice([0.0, 1.0])
        random.uniform(1000, 20000)
        tcp_flags_index = 0.0 if tcp_connection_syn == 1.0 else 1
    elif traffic_type == "Port_Scanning":
        ip_src_host = random.choice([0, 1, 2, 3, 4, 5])
        ip_dst_host = random.randint(0, 10)
        tcp_connection_syn = random.choice([0.0, 1.0])
        tcp_connection_synack = random.choice([0.0, 1.0])
        if ip_src_host == 3:
            tcp_dstport = 80.0
        else:
            tcp_dstport = random.uniform(0, 10000)
        tcp_len = 0.0
        tcp_seq = random.choice([0.0, 1.0])
        tcp_flags_index = 0.0 if tcp_connection_syn == 1.0 else random.choice([1, 2])
    else:
        raise ValueError("Invalid traffic type")

    return [frame_time, ip_src_host, ip_dst_host, tcp_connection_syn, tcp_connection_synack, tcp_dstport, tcp_len,
            tcp_seq, traffic_type, tcp_flags_index]


def generate_random_data(num_samples, traffic_type):
    data = []
    for _ in range(num_samples):
        data.append(generate_sample(traffic_type))

    columns = ['frame-time', 'ip-src_host', 'ip-dst_host', 'tcp-connection-syn', 'tcp-connection-synack', 'tcp-dstport',
               'tcp-len', 'tcp-seq', 'Attack_type', 'tcp-flags_index']
    return pd.DataFrame(data, columns=columns)


traffic_types = {
    "normal-traffic": "Normal",
    "port-scanning": "Port_Scanning",
    "ddos-tcp-syn-flood": "DDoS_TCP"
}
for filename, traffic_type in traffic_types.items():
    validation_data = generate_random_data(10000, traffic_type)
    validation_data.to_csv(f'generated_data/{filename}-preprocessed.csv', index=False)
