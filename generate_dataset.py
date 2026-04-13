import csv
import random
from datetime import datetime, timedelta

random.seed(42)

AUTHORIZED_MACS = [
    "AA:BB:CC:DD:EE:01",
    "AA:BB:CC:DD:EE:02",
    "AA:BB:CC:DD:EE:03",
    "AA:BB:CC:DD:EE:04",
    "AA:BB:CC:DD:EE:05",
]

UNAUTHORIZED_MACS = [
    "11:22:33:44:55:66",
    "FF:EE:DD:CC:BB:AA",
    "DE:AD:BE:EF:00:01",
]

NODES = ["NODE_01", "NODE_02", "NODE_03", "NODE_04", "NODE_05"]
PROTOCOLS = ["MQTT", "CoAP", "Zigbee", "LoRa"]

rows = []
base_time = datetime(2024, 1, 1, 10, 0, 0)

for i in range(200):
    ts = base_time + timedelta(seconds=i * 2)
    node = random.choice(NODES)

    # ~15% anomalous
    anomaly_type = random.randint(1, 100)

    if anomaly_type <= 8:
        # DoS - high transmission rate
        mac = random.choice(AUTHORIZED_MACS)
        pkt_size = random.randint(400, 1500)
        tx_rate = random.randint(600, 1200)
        status = "Anomalous"
        anomaly_reason = "High Transmission Rate"
    elif anomaly_type <= 15:
        # Unauthorized MAC
        mac = random.choice(UNAUTHORIZED_MACS)
        pkt_size = random.randint(64, 512)
        tx_rate = random.randint(2, 30)
        status = "Anomalous"
        anomaly_reason = "Unauthorized MAC"
    else:
        mac = random.choice(AUTHORIZED_MACS)
        pkt_size = random.randint(64, 512)
        tx_rate = random.randint(1, 50)
        status = "Normal"
        anomaly_reason = "None"

    rows.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "node_id": node,
        "mac_address": mac,
        "packet_size": pkt_size,
        "transmission_rate": tx_rate,
        "protocol": random.choice(PROTOCOLS),
        "status": status,
        "anomaly_reason": anomaly_reason
    })

with open("wsn_packet_logs.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print("Dataset generated: wsn_packet_logs.csv (200 rows)")
