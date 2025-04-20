from scapy.all import rdpcap, TCP, UDP, IP # Работать с пакетами, особенно с TCP, UDP и IP

# Читаем файл с сетевыми пакетами
packets = rdpcap('backup.pcapng')

# Список для странных пакетов
suspicious_packets = []

# G=Проходимся по всем пакетам
for pkt in packets:
    # Есть ли IP у пакета
    if IP in pkt:
        # Откуда и куда идет пакет (IPшники)
        ip_layer = pkt[IP]

        # Пока что пакет не странный
        is_suspicious = False

        # Есть ли контрольные флаги и номера портов у пакета
        # TCP - Надежная передача данных
        # Сайт, почта
        if TCP in pkt:
            # Какой флаг и какой порт
            tcp_layer = pkt[TCP]
            # Флаги
            flags = tcp_layer.flags

            # 0x01 - Завершить соединение; 0х02 - Начать соединение
            # Есть ли одновременно флаг 1 и 2
            # В нормальных условиях они не могут быть вместе
            if flags & 0x02 and flags & 0x01:
                # Пакет странный
                is_suspicious = True

            # Пакет пришел на редкий и номер маленький порт
            if tcp_layer.dport not in [80, 443, 21, 22, 25, 53] and tcp_layer.dport < 1024:
                # Пакет странный
                is_suspicious = True

        # У пакета слой UPD(быстрый но не надежный)
        # Видео, игра, DNS
        elif UDP in pkt:
            # Куда пакет идет
            udp_layer = pkt[UDP]

            # Если пришло не на DNS или UDP, то пакет странный
            if udp_layer.dport not in [53, 123]:
                is_suspicious = True

        # Если пакет слишком большой, он странный
        if len(pkt) > 1500:
            is_suspicious = True

        # Если хоть что-то странное, то записываем его в список
        if is_suspicious:
            suspicious_packets.append(pkt)

print(f"Обноружены подазрительные пакеты: {len(suspicious_packets)}")

# Проходимся по первым 10 странных пакетов
# i - Порядковый номер пакета, sp - Пакет
# enumerate возращает и индекс и сам элемент
for i, sp in enumerate(suspicious_packets[:10]):
    # summary() — Специальная функция Scapy, которая красиво показывает сводку о пакете: откуда, куда, какой протокол и так далее
    print(f"[{i+1}] {sp.summary()}")