from datetime import datetime, timedelta
import os
import random

import numpy as np
import pandas as pd

TRAFFIC_TYPES = {
    "normal-traffic": "Normal",
    "port-scanning": "Port_Scanning",
    # "ddos-tcp-syn-flood": "DDoS_TCP"
}
    
def generate_logs_for_traffic(traffic_type, logs_count):
    match traffic_type:
        case 'Normal':
            return generate_logs_for_normal_traffic(logs_count)
        case 'Port_Scanning':
            return generate_logs_for_port_scanning(logs_count)
        # case 'DDoS_TCP':
            # return generate_logs_for_ddos_tcp(logs_count)
        
def generate_logs_for_normal_traffic(logs_count):
    logs = []
    previous_timestamp = datetime.now().astimezone()
    for i in range(0, logs_count):
        logs.append(generate_normal_traffic_log(previous_timestamp))
        previous_timestamp = datetime.strptime(logs[-1][0], '%Y-%m-%dT%H:%M:%S.%f%z')
    return logs

def generate_normal_traffic_log(previous_timestamp):
    frame_time = (previous_timestamp + timedelta(milliseconds=random.randint(5, 20))).strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    arp_opcode = 0.0
    arp_hw_siz = 0.0
    ip_src_host = draw_ip_address()
    ip_dst_host = draw_ip_address()
    tcp_ack = np.random.choice([0.0, 1.0, 5.0, 6.0, 15.0, 56.0, 59.0], p=[0.13, 0.24, 0.13, 0.19, 0.06, 0.06, 0.19])
    tcp_ack_raw = 0.0 if np.random.choice([0.0, 1.0], p=[0.2, 0.8]) == 0.0 else random.randint(9749767.0, 4292762365.0)
    tcp_connection_fin = np.random.choice([0.0, 1.0], p=[0.88, 0.12])
    tcp_connection_rst = np.random.choice([0.0, 1.0], p=[0.88, 0.12])
    tcp_connection_syn = np.random.choice([0.0, 1.0], p=[0.92, 0.08])
    tcp_connection_synack = np.random.choice([0.0, 1.0], p=[0.93, 0.07])
    tcp_dstport = random.randint(51173, 65156)
    tcp_srcport = random.randint(51173, 65156)
    tcp_len = np.random.choice([0.0, 2.0, 4.0, 14.0, 41.0], p=[0.76, 0.06, 0.06, 0.06, 0.06])
    tcp_seq = np.random.choice([0.0, 1.0, 5.0, 6.0, 15.0, 56.0, 59.0], p=[0.13, 0.24, 0.13, 0.19, 0.06, 0.06, 0.19])
    tcp_flags = np.random.choice(
        ['0.0', '0x00000002', '0x00000004', '0x00000010', '0x00000011', '0x00000012', '0x00000018', '0x00000019'], 
        p=[0.01, 0.06, 0.12, 0.44, 0.06, 0.07, 0.18, 0.06]
    )
    tcp_flags_ack = np.random.choice([0.0, 1.0], p=[0.24, 0.76])
    udp_port = 0.0
    udp_stream = 0.0
    udp_time_delta = 0.0
    dns_qry_name = 0.0
    dns_qry_name_len = 0
    dns_qry_qu = 0
    dns_qry_type = 0.0
    dns_retransmission = 0.0
    dns_retransmit_request = 0.0
    dns_retransmit_request_in = 0.0
    mqtt_conack_flags = np.random.choice(['0', '0x00000000'], p=[0.93, 0.07])
    mqtt_conflag_cleansess = np.random.choice([0.0, 1.0], p=[0.94, 0.06])
    mqtt_conflags = np.random.choice(['0', '0x00000002'], p=[0.93, 0.07])
    mqtt_hdrflags = np.random.choice(
        ['0.0', '0x00000010', '0x00000020', '0x00000030', '0x000000e0'], 
        p=[0.76, 0.06, 0.06, 0.06, 0.06]
    )
    mqtt_len = np.random.choice([0, 0.0, 2.0, 12.0, 39.0], p=[0.76, 0.06, 0.06, 0.06, 0.06])
    mqtt_msg = 0
    mqtt_msgtype = np.random.choice([0.0, 1.0, 2.0, 3.0, 14.0], p=[0.76, 0.06, 0.06, 0.06, 0.06])
    mqtt_proto_len = np.random.choice([0, 4.0], p=[0.94, 0.06])
    mqtt_protoname = np.random.choice(['0', 'MQTT'], p=[0.94, 0.06])
    mqtt_topic = 0
    mqtt_topic_len = 0.0
    mqtt_ver = np.random.choice([0, 4.0], p=[0.94, 0.06])

    return [frame_time, arp_opcode, arp_hw_siz, ip_src_host, ip_dst_host, tcp_ack, tcp_ack_raw,
            tcp_connection_fin, tcp_connection_rst, tcp_connection_syn, tcp_connection_synack,
            tcp_dstport, tcp_srcport, tcp_len, tcp_seq, tcp_flags, tcp_flags_ack, udp_port, 
            udp_stream, udp_time_delta, dns_qry_name, dns_qry_name_len, dns_qry_qu, dns_qry_type, 
            dns_retransmission, dns_retransmit_request, dns_retransmit_request_in, mqtt_conack_flags, 
            mqtt_conflag_cleansess, mqtt_conflags, mqtt_hdrflags, mqtt_len, mqtt_msg, mqtt_msgtype, 
            mqtt_proto_len, mqtt_protoname, mqtt_topic, mqtt_topic_len, mqtt_ver,'Normal']
    
def generate_logs_for_port_scanning(logs_count):
    logs = []
    hacker_ip = draw_ip_address()
    victim_ip = draw_ip_address()
    victim_port = 1000
    previous_timestamp = datetime.now().astimezone()
    for i in range(0, int(logs_count/2)):
        logs.extend(generate_port_scanning_log_pair(previous_timestamp, hacker_ip, victim_ip, victim_port))
        previous_timestamp = datetime.strptime(logs[-1][0], '%Y-%m-%dT%H:%M:%S.%f%z')
        victim_port += 1
    return logs
        
def generate_port_scanning_log_pair(previous_timestamp, hacker_ip, victim_ip, victim_port):
    frame_time = (previous_timestamp + timedelta(milliseconds=random.randint(1, 5))).strftime('%Y-%m-%dT%H:%M:%S.%f%z')
    hacker_port = 80
    tcp_connection_synack = 0.0
    tcp_len = 0.0
    arp_opcode = 0.0
    arp_hw_siz = 0.0
    tcp_ack = random.randint(341294.0, 2147250934.0)
    tcp_connection_fin = 0.0
    tcp_connection_synack = 0.0
    tcp_len = 0.0
    udp_port = 0.0
    udp_stream = 0.0
    udp_time_delta = 0.0
    dns_qry_name = 0.0
    dns_qry_name_len = 0.0
    dns_qry_qu = 0.0
    dns_qry_type = 0.0
    dns_retransmission = 0.0
    dns_retransmit_request = 0.0
    dns_retransmit_request_in = 0.0
    mqtt_conack_flags = 0.0
    mqtt_conflag_cleansess = 0.0
    mqtt_conflags = 0.0
    mqtt_hdrflags = 0.0
    mqtt_len = 0.0
    mqtt_msg = 0.0
    mqtt_msgtype = 0.0
    mqtt_proto_len = 0.0
    mqtt_protoname = 0.0
    mqtt_topic = 0.0
    mqtt_topic_len = 0.0
    mqtt_ver = 0.0
    traffic_type = 'Port_Scanning'

    return [
            [
                frame_time, arp_opcode, arp_hw_siz, hacker_ip, victim_ip, 1.0, tcp_ack, tcp_connection_fin, 
                1.0, 0.0, tcp_connection_synack,victim_port, hacker_port, tcp_len, 1.0, '0x00000014', 1.0, 
                udp_port, udp_stream, udp_time_delta, dns_qry_name, dns_qry_name_len, dns_qry_qu, dns_qry_type, 
                dns_retransmission, dns_retransmit_request, dns_retransmit_request_in, mqtt_conack_flags, 
                mqtt_conflag_cleansess, mqtt_conflags, mqtt_hdrflags, mqtt_len, mqtt_msg, mqtt_msgtype, 
                mqtt_proto_len, mqtt_protoname, mqtt_topic, mqtt_topic_len, mqtt_ver, traffic_type
            ],
            [
                frame_time, arp_opcode, arp_hw_siz, victim_ip, hacker_ip, tcp_ack, tcp_ack, tcp_connection_fin, 
                0.0, 1.0, tcp_connection_synack,hacker_port, victim_port, tcp_len, 0.0, '0x00000002', 0.0, 
                udp_port, udp_stream, udp_time_delta, dns_qry_name, dns_qry_name_len, dns_qry_qu, dns_qry_type, 
                dns_retransmission, dns_retransmit_request, dns_retransmit_request_in, mqtt_conack_flags, 
                mqtt_conflag_cleansess, mqtt_conflags, mqtt_hdrflags, mqtt_len, mqtt_msg, mqtt_msgtype, 
                mqtt_proto_len, mqtt_protoname, mqtt_topic, mqtt_topic_len, mqtt_ver,traffic_type
            ]
        ]

def draw_ip_address():
    return str(random.randint(0, 255)) + '.' \
        + str(random.randint(0, 255)) + '.' \
        + str(random.randint(0, 255)) + '.' \
        + str(random.randint(0, 255))

outdir = './generated_data'
if not os.path.exists(outdir):
    os.mkdir(outdir)

columns = [
    "frame-time",
    "arp-opcode",
    "arp-hw-size",
    "ip-src_host",
    "ip-dst_host",
    "tcp-ack",
    "tcp-ack_raw",
    "tcp-connection-fin",
    "tcp-connection-rst",
    "tcp-connection-syn",
    "tcp-connection-synack",
    "tcp-dstport",
    "tcp-flags_index",
    "tcp-flags-ack",
    "tcp-len",
    "tcp-seq",
    "tcp-srcport",
    "udp-port",
    "udp-stream",
    "udp-time_delta",
    "dns-qry-name",
    "dns-qry-name-len_index",
    "dns-qry-qu_index",
    "dns-qry-type",
    "dns-retransmission",
    "dns-retransmit_request",
    "dns-retransmit_request_in",
    "mqtt-conack-flags_index",
    "mqtt-conflag-cleansess",
    "mqtt-conflags_index",
    "mqtt-hdrflags_index",
    "mqtt-len",
    "mqtt-msg_index",
    "mqtt-msgtype",
    "mqtt-proto_len",
    "mqtt-protoname_index",
    "mqtt-topic_index",
    "mqtt-topic_len",
    "mqtt-ver",
    "Attack_type"
]
    
for filename, traffic_type in TRAFFIC_TYPES.items():
    logs = generate_logs_for_traffic(traffic_type, 10000)
    
    data = pd.DataFrame(logs, columns=columns)
    print(f'Saving data to file: {outdir}/{filename}.csv')
    data.to_csv(f'{outdir}/{filename}.csv', index=False)