from  scapy.all import rdpcap, IP, TCP, UDP  # Scapy — Это библиотека, которая умеет читать и анализировать сетевой трафик
import pandas as pd  # pandas — Она помогает работать с таблицами, как с Excel
from sklearn.ensemble import IsolationForest  # Mодель машинного обучения, которая умеет находить странные элементы в данных
import datetime  # Библиотека для работы со временем

# Читаем файл с сетевыми пакетами
packets = rdpcap("backup.pcapng")

# Список для полезных признаков пакета
features = []
# Хранение времени предыдущего пакета
last_timestamp = None

# Перебираем все пакеты
for pkt in packets:
    # Есть ли у пакета адресс получателя и отправителя
    if IP in pkt:
        # IP пакета
        ip_layer = pkt[IP]
        # Какой протокол используется: TCP, UDP и т.д.
        proto = ip_layer.proto
        # Длинна пакета (сколько весит) в байтах
        lenght = len(pkt)
        # Когда пакет был получен
        time =pkt.time
        # Разница, между этим и предыдущем пакетом
        time_diff = 0

        # Если это не первый пакет, то считаем время с предыдущего пакета
        if last_timestamp is not None:
            time_diff = time - last_timestamp
        # Обновляем время (этот пакет становится предыдущем для следующей итерации)
        last_timestamp = time

        # src_port и dst_port — Номера портов (отправитель и получатель)
        src_port = dst_port = 0
        # flags — Специальные флажки TCP
        flags = 0

        # Есть ли контрольные флаги и номера портов у пакета
        # TCP - Надежная передача данных
        # Сайт, почта
        if TCP in pkt:
            tcp_layer = pkt[TCP]
            # Порт отправителя, порт получателя, флаги
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = int(tcp_layer.flags)
        # У пакета слой UPD(быстрый но не надежный)
        # Видео, игра, DNS
        elif UDP in pkt:
            udp_layer = pkt[UDP]
            # Порты отправителя и получателя
            src_port = udp_layer.sport
            dst_port = udp_layer.dport

        # Добовляем в список признаки(данные) пакета
        features.append([
            lenght,
            proto,
            src_port,
            dst_port,
            flags,
            time_diff
        ])

# Создаем таблицу
df = pd.DataFrame(features, columns=['lenght', 'proto', 'src_port', 'dst_port', 'flags', 'time_diff'])

# Настраиваем модель "Лес из 100 деревьев", которая будет искать 5% самых подозрительных пакетов и зерно случайности 42
model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
# Обучаем модель. Узнает как выглядит нормальный пакет
model.fit(df)

# Предсказываем для каждого пакета — нормальный (1) или аномалия (-1)
preds = model.predict(df)

# Добавляем новый столбец в таблицу
df["anomaly"] = preds


# Отбираем только те строки, где модель нашла аномалию
anomalies = df[df["anomaly"] == -1]
print(f"Обноруженно аномалий: {len(anomalies)} из {len(df)} пакетов")

print(anomalies.head(10))