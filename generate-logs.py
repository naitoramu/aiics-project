import os
import pandas as pd
from datetime import datetime, timedelta
import random


def random_date(start, end):
    return start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))


start_date = datetime(2024, 5, 13, 16, 0, 0)
end_date = datetime(2024, 5, 13, 19, 2, 37)


def generate_sample(traffic_type, previous_log_timestamp):
    if traffic_type == "Normal":
        td = random.randint(5, 20)
        frame_time = previous_log_timestamp + timedelta(milliseconds=td)
        return [generate_normal_log(frame_time.strftime('%Y-%m-%dT%H:%M:%S.%f%z'))]
    elif traffic_type == "DDoS_TCP":
        frame_time = previous_log_timestamp + timedelta(milliseconds=1) if random.randint(1, 10) == 1 else previous_log_timestamp
        return [generate_ddos_log(frame_time.strftime('%Y-%m-%dT%H:%M:%S.%f%z'))]
    elif traffic_type == "Port_Scanning":
        td = random.randint(1, 5)
        frame_time = previous_log_timestamp + timedelta(milliseconds=td)
        return generate_port_scan_log_pair(frame_time.strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
    else:
        raise ValueError("Invalid traffic type")


def generate_port_scan_log_pair(frame_time):
    attacker_ip = 1.0
    victim_ip = 2.0
    attacker_port = 80
    victim_port = random.randint(0, 7000)
    tcp_connection_synack = 0.0
    tcp_len = 0.0

    return [
        [frame_time, attacker_ip, victim_ip, 0.0, tcp_connection_synack, victim_port, tcp_len, 1.0, attacker_port, traffic_type, 1.0],
        [frame_time, victim_ip, attacker_ip, 1.0, tcp_connection_synack, attacker_port, tcp_len, 0.0, victim_port, traffic_type, 0.0],
    ]


def generate_ddos_log(frame_time):
    tcp_dstport = random.randint(1000, 70000)
    ip_src_host = random.randint(50000, 300000)
    ip_dst_host = random.randint(50000, 300000)
    tcp_connection_syn = random.choice([0.0, 1.0])
    tcp_connection_synack = random.choice([0.0, 1.0])
    tcp_seq = random.choice([0.0, 1.0])
    if tcp_dstport == 80.0:
        tcp_len = 120.0
        tcp_flags_index = 0.0
    else:
        tcp_len = random.choice([0.0, 120.0])
        tcp_flags_index = random.choice([0.0, 1.0])
    random.uniform(1000, 20000)
    tcp_flags_index = 0.0 if tcp_connection_syn == 1.0 else tcp_flags_index

    return [frame_time, ip_src_host, ip_dst_host, tcp_connection_syn, tcp_connection_synack, tcp_dstport, tcp_len,
            tcp_seq, 80.0, traffic_type, tcp_flags_index]


def generate_normal_log(frame_time):
    ip_src_host = random.randint(0, 10)
    ip_dst_host = random.randint(0, 10)
    tcp_connection_syn = random.choice([0.0, 1.0])
    tcp_connection_synack = random.choice([0.0, 1.0])
    tcp_dstport = random.randint(0, 7000)
    tcp_srcport = random.randint(0, 7000)
    tcp_len = random.uniform(0, 1500)
    tcp_seq = random.uniform(0, 500000)
    tcp_flags_index = 4.0 if tcp_connection_syn == 1.0 else random.choice([0, 1, 2, 3, 5, 6, 7])

    return [frame_time, ip_src_host, ip_dst_host, tcp_connection_syn, tcp_connection_synack, tcp_dstport, tcp_len,
            tcp_seq, tcp_srcport, traffic_type, tcp_flags_index]


def generate_random_data(num_samples, traffic_type):
    data = []
    num_samples = num_samples if traffic_type != "Port_Scanning" else int(num_samples/2)
    previous_timestamp = datetime.now().astimezone()
    for i in range(num_samples):
        sample = generate_sample(traffic_type, previous_timestamp)
        data.extend(sample)
        previous_timestamp = datetime.strptime(data[-1][0], '%Y-%m-%dT%H:%M:%S.%f%z')

    columns = ['frame-time', 'ip-src_host', 'ip-dst_host', 'tcp-connection-syn', 'tcp-connection-synack', 'tcp-dstport',
               'tcp-len', 'tcp-seq', 'tcp-srcport', 'Attack_type', 'tcp-flags_index']
    return pd.DataFrame(data, columns=columns)


traffic_types = {
    "normal-traffic": "Normal",
    "port-scanning": "Port_Scanning",
    "ddos-tcp-syn-flood": "DDoS_TCP"
}
outdir = './generated_data'
if not os.path.exists(outdir):
    os.mkdir(outdir)
for filename, traffic_type in traffic_types.items():
    validation_data = generate_random_data(10000, traffic_type)
    print(f'Saving data to file: {outdir}/{filename}-preprocessed.csv')
    validation_data.to_csv(f'{outdir}/{filename}-preprocessed.csv', index=False)
