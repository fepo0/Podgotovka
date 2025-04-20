from scapy.all import rdpcap, IP  # Прочитать интернет-пакеты из файла
import pandas as pd  # pandas — Она помогает работать с таблицами, как с Excel
import matplotlib.pyplot as plt  # Рисовать графики.
from sklearn.ensemble import GradientBoostingRegressor  # Умная модель — она умеет предсказывать числа GradientBoostingRegressor "прогнозист"
from sklearn.model_selection import train_test_split  # Функция для разделения данных на обучение и тестирование
from sklearn.metrics import mean_squared_error  # Наколько хорошо модель предсказывает
import numpy as np  # Работа с числами и массивами

# Читаем файл с сетевыми пакетами
packets = rdpcap("backup.pcapng")

# Данные по времени
time_series = []

# Проходимся по каждому пакету
for pkt in packets:
    # Есть ли у пакета адресс получателя и отправителя
    if IP in pkt:
        # Сохраняем время, когда пришел пакет (секунды)
        timestamp = int(pkt.time)
        # Какой размер пакета (байт)
        length = len(pkt)
        # Добавадляем в список кортеж (Время и размер)
        time_series.append((timestamp, length))

# Создаем таблицу
df = pd.DataFrame(time_series, columns=['time', 'length'])
# Группируем пакеты по секундам (складываем все байты пришедшие в одну секунду)
# Сколько байт в каждую секунду
df_grouped = df.groupby('time').sum().reset_index()

# Функция, которая делает лаги, берёт прошлые значения, чтобы предсказать будущее
def create_lags(data, lag=5):
    # Создаем таблицу для лагов
    df_lag = pd.DataFrame()
    # Для каждого лага сдвигаем лаги назад
    for i in range(lag):
        df_lag[f"lag_{i+1}"] = data.shift(i + 1)
    # Записываем текущее значение, которое хотим предсказать
    df_lag["target"] = data.values
    # Удаляем строки, где не хватает данных
    df_lag.dropna(inplace=True)
    # Возращаем таблицу
    return df_lag

# Создаем временные лаги
lagged_df = create_lags(df_grouped["length"])

# X - Прошлые значения (модель будет учиться)
X = lagged_df.drop("target", axis=1)
# Y - Значения, которые хотим предсказать
y = lagged_df["target"]

# Делим данные на тренировку и тест
# Обучим модель на 80% данных, а на остальных 20% — проверим, как она справляется
# shuffle=False — Значит не перемешиваем, ведь это временной ряд, важен порядок
X_train, X_test, y_train, y_test = train_test_split(X, y, shuffle=False, test_size=0.2)

# Создаем модель градиентного бустинга (предсказывать значения)
model = GradientBoostingRegressor()
# Обучаем модель на тренировочных данных
model.fit(X_train, y_train)

# Модель делает предсказание на тестовых данных
y_pred = model.predict(X_test)
# Сравниваем настоящие и предсказание
# MSE (среднеквадратичная ошибка) показывает: насколько сильно ошибается модель. Чем меньше тем лучше
mse = mean_squared_error(y_pred, y_test)
print(f"Среднеквадратичная ошибка: {mse:.2f}")

# Создаём график размером 12x6 дюймов
plt.figure(figsize=(12,6))
# Реальные данные
plt.plot(range(len(y_test)), y_test.values, label="Реальное значение")
# Предсказание модели
plt.plot(range(len(y_pred)), y_pred, label="Прогноз")
# Подписи, заголовок, сетка
plt.legend()
plt.title("Прогноз сетевой нагрузки")
plt.xlabel("Время")
plt.ylabel("Байты в секунду")
plt.grid(True)
# Сохроняем картинку
plt.savefig("Zadanye3.png")