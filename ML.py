from  scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
from sklearn.ensemble import IsolationForest
import datetime

packets = rdpcap("backup.pcapng")

features = []
last_timestamp = None

for pkt in packets:
    if IP in pkt:
        ip_layer = pkt[IP]
        proto = ip_layer.proto
        lenght = len(pkt)
        time =pkt.time
        time_diff = 0

        if last_timestamp is not None:
            time_diff = time - last_timestamp
        last_timestamp = time

        src_port = dst_port = 0
        flags = 0

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = int(tcp_layer.flags)
        elif UDP in pkt:
            udp_layer = pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport

        features.append([
            lenght,
            proto,
            src_port,
            dst_port,
            flags,
            time_diff
        ])

df = pd.DataFrame(features, columns=['lenght', 'proto', 'src_port', 'dst_port', 'flags', 'time_diff'])

model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(df)

preds = model.predict(df)

df["anomaly"] = preds

anomalies = df[df["anomaly"] == -1]
print(f"Обноруженно аномалий: {len(anomalies)} из {len(df)} пакетов")

print(anomalies.head(10))