import sys
import random
import datetime
import re
import threading
import time

import pandas as pd
from faker import Faker
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
import numpy as np

from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QVBoxLayout,
    QTextEdit, QHBoxLayout, QComboBox, QSplitter
)
from PyQt5.QtCore import QTimer, Qt

import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# ---- GLOBALS ----
fake = Faker()
methods = ['GET', 'POST', 'PUT', 'DELETE']
status_codes_normal = [200, 201, 202, 204, 301, 302]
status_codes_anomaly = [400, 401, 403, 404, 500, 502, 503, 504]
urls = [
    "/home", "/login", "/dashboard", "/user/profile", "/search?q=data",
    "/settings", "/api/data", "/logout", "/admin", "/register"
]

real_time_generating = False
analyze_running = False
log_file = "realtime_logs.txt"

# ---- LOG GENERATION FUNCTIONS ----

def generate_normal_log():
    timestamp = fake.date_time_between(start_date='-30d', end_date='now').strftime('%Y-%m-%d %H:%M:%S')
    ip = fake.ipv4()
    method = random.choice(methods)
    url = random.choice(urls)
    status = random.choice(status_codes_normal)
    return f"[{timestamp}] {ip} {method} {url} {status}"

def generate_intermediate_log():
    timestamp = fake.date_time_between(start_date='-30d', end_date='now').strftime('%Y-%m-%d %H:%M:%S')
    ip = fake.ipv4()
    method = random.choice(methods)
    url = random.choice(urls)
    status = random.choice(status_codes_normal)

    glitch = random.choice(['ip', 'method', 'url', 'status'])

    if glitch == 'ip':
        ip = ip[:-1] + str(random.randint(0,9))  # Slightly wrong IP
    elif glitch == 'method':
        method = method.lower()  # lowercase method like "get"
    elif glitch == 'url':
        url += random.choice(['/temp', '/1', '/xx'])  # minor URL glitch
    elif glitch == 'status':
        status = random.choice([99, 600, 399, 601])  # slightly out of range

    return f"[{timestamp}] {ip} {method} {url} {status}"

def generate_anomalous_log():
    anomaly_type = random.choice(['timestamp', 'ip', 'method', 'url', 'status'])

    timestamp = fake.date_time_between(start_date='-30d', end_date='now').strftime('%Y-%m-%d %H:%M:%S')
    ip = fake.ipv4()
    method = random.choice(methods)
    url = random.choice(urls)
    status = random.choice(status_codes_normal)

    if anomaly_type == 'timestamp':
        timestamp = "BAD_TIMESTAMP"
    elif anomaly_type == 'ip':
        ip = "999.999.999.999"
    elif anomaly_type == 'method':
        method = "INVALID_METHOD"
    elif anomaly_type == 'url':
        url = "/unknown/illegal/page/!!!"
    elif anomaly_type == 'status':
        status = random.choice([-1, 700, 999])

    return f"[{timestamp}] {ip} {method} {url} {status}"

def real_time_log_generator():
    global real_time_generating

    with open(log_file, "w") as f:
        while real_time_generating:
            rand = random.random()
            if rand < 0.8:
                log = generate_normal_log()
            elif rand < 0.9:
                log = generate_intermediate_log()
            else:
                log = generate_anomalous_log()
            f.write(log + "\n")
            f.flush()
            time.sleep(random.uniform(0.5, 1.5))

# ---- ANOMALY DETECTION FUNCTIONS ----

def parse_log_line(line):
    pattern = r'\[(.*?)\]\s+(.*?)\s+(.*?)\s+(.*?)\s+(.*)'
    match = re.match(pattern, line)
    if match:
        timestamp, ip, method, url, status = match.groups()
        return {
            'timestamp': timestamp,
            'ip': ip,
            'method': method,
            'url': url,
            'status': status
        }
    else:
        return None

def load_logs():
    try:
        with open(log_file, 'r') as file:
            lines = file.readlines()
        parsed_logs = [parse_log_line(line.strip()) for line in lines]
        parsed_logs = [log for log in parsed_logs if log is not None]
        return pd.DataFrame(parsed_logs)
    except Exception:
        return pd.DataFrame()

def valid_ip(ip):
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    for part in parts:
        if not part.isdigit() or int(part) < 0 or int(part) > 255:
            return False
    return True

def feature_engineering(df):
    if df.empty:
        return pd.DataFrame()

    df['status'] = pd.to_numeric(df['status'], errors='coerce')
    df['invalid_timestamp'] = df['timestamp'].apply(lambda x: 1 if x == "BAD_TIMESTAMP" else 0)
    df['invalid_ip'] = df['ip'].apply(lambda x: 1 if not valid_ip(x) else 0)
    df['invalid_method'] = df['method'].apply(lambda x: 1 if x.upper() not in ['GET', 'POST', 'PUT', 'DELETE'] else 0)
    df['invalid_url'] = df['url'].apply(lambda x: 1 if '!!!' in x or 'unknown' in x else 0)
    df['invalid_status'] = df['status'].apply(lambda x: 1 if (pd.isna(x) or x < 100 or x > 599) else 0)

    features = df[['invalid_timestamp', 'invalid_ip', 'invalid_method', 'invalid_url', 'invalid_status']]
    return features

def detect_anomalies(features):
    if features.empty:
        return []
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(features)
    preds = model.predict(features)
    return preds

# ---- PyQt5 GUI ----

class RealTimeAnomalyApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Real-Time Big Data Security - Anomaly Detection")
        self.setGeometry(200, 200, 1300, 700)

        layout = QVBoxLayout()

        self.start_button = QPushButton("Start Real-Time System")
        self.start_button.clicked.connect(self.start_system)

        self.stop_button = QPushButton("Stop System")
        self.stop_button.clicked.connect(self.stop_system)

        self.graph_type = QComboBox()
        self.graph_type.addItems(["Bar Chart", "Scatter Plot", "Line Chart", "DBSCAN Clustering"])

        top_layout = QHBoxLayout()
        top_layout.addWidget(self.start_button)
        top_layout.addWidget(self.stop_button)
        top_layout.addWidget(QLabel("Select Graph Type:"))
        top_layout.addWidget(self.graph_type)

        splitter = QSplitter(Qt.Vertical)

        self.figure, self.ax = plt.subplots()
        self.canvas = FigureCanvas(self.figure)

        self.anomaly_text = QTextEdit()
        self.anomaly_text.setReadOnly(True)

        splitter.addWidget(self.canvas)
        splitter.addWidget(self.anomaly_text)

        layout.addLayout(top_layout)
        layout.addWidget(splitter)

        self.setLayout(layout)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_analysis)

    def start_system(self):
        global real_time_generating, analyze_running

        if not real_time_generating:
            real_time_generating = True
            threading.Thread(target=real_time_log_generator, daemon=True).start()

        analyze_running = True
        self.timer.start(3000)

        self.anomaly_text.append("▶️ Started real-time log generation and analysis...\n")

    def stop_system(self):
        global real_time_generating, analyze_running

        real_time_generating = False
        analyze_running = False
        self.timer.stop()
        self.anomaly_text.append("⏹️ Stopped real-time system.\n")

    def update_analysis(self):
        df_logs = load_logs()
        if df_logs.empty:
            return

        features = feature_engineering(df_logs)
        preds = detect_anomalies(features)

        df_logs['anomaly'] = preds

        normal = (preds == 1).sum()
        anomalies = (preds == -1).sum()

        self.ax.clear()

        graph_choice = self.graph_type.currentText()
        if graph_choice == "Bar Chart":
            self.ax.bar(['Normal', 'Anomalies'], [normal, anomalies], color=['green', 'red'])
        elif graph_choice == "Scatter Plot":
            x = list(range(len(df_logs)))
            y = preds
            self.ax.scatter(x, y, c=['red' if p == -1 else 'green' for p in preds])
        elif graph_choice == "Line Chart":
            x = list(range(len(df_logs)))
            y = preds
            self.ax.plot(x, y, marker='o')
        elif graph_choice == "DBSCAN Clustering":
            if not features.empty:
                dbscan = DBSCAN(eps=0.5, min_samples=5)
                cluster_labels = dbscan.fit_predict(features)

                x = np.arange(len(cluster_labels))
                self.ax.scatter(x, cluster_labels, c=cluster_labels, cmap='rainbow', marker='o')
                self.ax.set_title('DBSCAN Clustering of Logs')

        self.ax.set_title('Real-Time Log Anomaly Detection')
        self.canvas.draw()

        anomalies_detected = df_logs[df_logs['anomaly'] == -1]
        self.anomaly_text.clear()
        self.anomaly_text.append(f"Total Logs: {len(df_logs)} | Normal: {normal} | Anomalies: {anomalies}\n\n")
        self.anomaly_text.append("🛑 Anomalies Detected:\n")

        for idx, row in anomalies_detected.iterrows():
            self.anomaly_text.append(
                f"[{row['timestamp']}] {row['ip']} {row['method']} {row['url']} {row['status']}"
            )

# ---- MAIN ----

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RealTimeAnomalyApp()
    window.show()
    sys.exit(app.exec_())
