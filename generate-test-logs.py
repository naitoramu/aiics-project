from datetime import datetime, timedelta
import os
import random

TRAFFIC_TYPES = {
    "normal-traffic": "Normal",
    # "port-scanning": "Port_Scanning",
    # "ddos-tcp-syn-flood": "DDoS_TCP"
}
    
def generate_logs_for_traffic(traffic_type, logs_count):
    match traffic_type:
        case 'Normal':
            return generate_logs_for_normal_traffic(logs_count)
        case 'Port_Scanning':
            return generate_logs_for_port_scanning(logs_count)
        case 'DDoS_TCP':
            return generate_logs_for_ddos_tcp(logs_count)
        
def generate_logs_for_normal_traffic(logs_count):
    logs = []
    previous_timestamp = datetime.now().astimezone()
    for i in range(0, logs_count):
        logs.append(generate_normal_traffic_log(previous_timestamp))
        previous_timestamp = logs[-1][0]
    return logs

def generate_normal_traffic_log(previous_timestamp):
    frame_time = (previous_timestamp + timedelta(milliseconds=random.randint(5, 20))).strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    ip_src_host = draw_ip_address()
    ip_dst_host = draw_ip_address()
    tcp_connection_syn = random.choice([0.0, 1.0], p=[0.92, 0.08])
    tcp_connection_synack = random.choice([0.0, 1.0], p=[0.93, 0.07])
    tcp_dstport = random.randint(51173, 65156)
    tcp_srcport = random.randint(51173, 65156)
    tcp_len = random.choice([0.0, 2.0, 4.0, 14.0, 41.0], p=[0.76, 0.06, 0.06, 0.06, 0.06])
    tcp_seq = random.choice([0.0, 1.0, 5.0, 6.0, 15.0, 56.0, 59.0], p=[0.13, 0.24, 0.13, 0.19, 0.06, 0.06, 0.19])
    tcp_flags = random.choice(
        ['0.0', '0x00000002', '0x00000004', '0x00000010', '0x00000011', '0x00000012', '0x00000018', '0x00000019'], 
        p=[0.01, 0.06, 0.12, 0.44, 0.06, 0.07, 0.18, 0.06]
    )

    return [frame_time, ip_src_host, ip_dst_host, tcp_connection_syn, tcp_connection_synack, tcp_dstport, tcp_len,
            tcp_seq, tcp_srcport, traffic_type, tcp_flags]
    

def draw_ip_address():
    return random.randint(0, 255) + '.' \
        + random.randint(0, 255) + '.' \
        + random.randint(0, 255) + '.' \
        + random.randint(0, 255)

outdir = './generated_data'
if not os.path.exists(outdir):
    os.mkdir(outdir)
for filename, traffic_type in TRAFFIC_TYPES.items():
    logs = generate_logs_for_traffic(traffic_type, 10000)
    print(f'Saving data to file: {outdir}/{filename}.csv')
    logs.to_csv(f'{outdir}/{filename}-preprocessed.csv', index=False)