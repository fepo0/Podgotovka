from scapy.all import rdpcap, IP
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import  GradientBoostingRegressor
from sklearn.model_selection import  train_test_split
from sklearn.metrics import mean_squared_error
import numpy as np

packets = rdpcap("backup.pcapng")

time_series = []

for pkt in packets:
    if IP in pkt:
        timestamp = int(pkt.time)
        length = len(pkt)
        time_series.append((timestamp, length))

df = pd.DataFrame(time_series, columns=['time', 'length'])
df_grouped = df.groupby('time').sum().reset_index()

def create_lags(data, lag=5):
    df_lag = pd.DataFrame()
    for i in range(lag):
        df_lag[f"lag_{i+1}"] = data.shift(i + 1)
    df_lag["target"] = data.values
    df_lag.dropna(inplace=True)
    return df_lag

lagged_df = create_lags(df_grouped["length"])

X = lagged_df.drop("target", axis=1)
y = lagged_df["target"]

X_train, X_test, y_train, y_test = train_test_split(X, y, shuffle=False, test_size=0.2)

model = GradientBoostingRegressor()
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
mse = mean_squared_error(y_pred, y_test)
print(f"Среднеквадратичная ошибка: {mse:.2f}")

plt.figure(figsize=(12,6))
plt.plot(range(len(y_test)), y_test.values, label="Реальное значение")
plt.plot(range(len(y_pred)), y_pred, label="Прогноз")
plt.legend()
plt.title("Прогноз сетевой нагрузки")
plt.xlabel("Время")
plt.ylabel("Байты в секунду")
plt.grid(True)
plt.savefig("Zadanye3.png")