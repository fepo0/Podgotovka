from scapy.all import rdpcap, TCP, UDP, IP

packets = rdpcap('backup.pcapng')

suspicious_packets = []

for pkt in packets:
    if IP in pkt:
        ip_layer = pkt[IP]

        is_suspicious = False

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            flags = tcp_layer.flags

            if flags & 0x02 and flags & 0x01:
                is_suspicious = True

            if tcp_layer.dport not in [80, 443, 21, 22, 25, 53] and tcp_layer.dport < 1024:
                is_suspicious = True

        elif UDP in pkt:
            udp_layer = pkt[UDP]

            if udp_layer.dport not in [53, 123]:
                is_suspicious = True

        if len(pkt) > 1500:
            is_suspicious = True

        if is_suspicious:
            suspicious_packets.append(pkt)

print(f"Обноружены подазрительные пакеты: {len(suspicious_packets)}")
for i, sp in enumerate(suspicious_packets[:10]):
    print(f"[{i+1}] {sp.summary()}")