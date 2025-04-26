import random
import datetime
import faker

# Install faker first if needed: pip install faker

# Initialize Faker for realistic data
fake = faker.Faker()

# Settings
NUM_NORMAL_LOGS = 9000
NUM_ANOMALOUS_LOGS = 1000

# Log template: [timestamp] IP METHOD URL STATUS_CODE
methods = ['GET', 'POST', 'PUT', 'DELETE']
status_codes_normal = [200, 201, 202, 204, 301, 302]
status_codes_anomaly = [400, 401, 403, 404, 500, 502, 503, 504]

urls = [
    "/home", "/login", "/dashboard", "/user/profile", "/search?q=data",
    "/settings", "/api/data", "/logout", "/admin", "/register"
]

# Helper functions
def generate_normal_log():
    timestamp = fake.date_time_between(start_date='-30d', end_date='now').strftime('%Y-%m-%d %H:%M:%S')
    ip = fake.ipv4()
    method = random.choice(methods)
    url = random.choice(urls)
    status = random.choice(status_codes_normal)
    return f"[{timestamp}] {ip} {method} {url} {status}"

def generate_anomalous_log():
    # Randomly decide type of anomaly
    anomaly_type = random.choice(['timestamp', 'ip', 'method', 'url', 'status'])

    timestamp = fake.date_time_between(start_date='-30d', end_date='now').strftime('%Y-%m-%d %H:%M:%S')
    ip = fake.ipv4()
    method = random.choice(methods)
    url = random.choice(urls)
    status = random.choice(status_codes_normal)

    if anomaly_type == 'timestamp':
        timestamp = "BAD_TIMESTAMP"
    elif anomaly_type == 'ip':
        ip = "999.999.999.999"  # Invalid IP
    elif anomaly_type == 'method':
        method = "INVALID_METHOD"
    elif anomaly_type == 'url':
        url = "/unknown/illegal/page/!!!"
    elif anomaly_type == 'status':
        status = random.choice([-1, 700, 999])  # Impossible HTTP codes

    return f"[{timestamp}] {ip} {method} {url} {status}"

# Main log generation
def generate_logs(filename="generated_logs.txt"):
    logs = []

    for _ in range(NUM_NORMAL_LOGS):
        logs.append(generate_normal_log())

    for _ in range(NUM_ANOMALOUS_LOGS):
        logs.append(generate_anomalous_log())

    # Shuffle logs to mix normal and anomalies
    random.shuffle(logs)

    # Write to file
    with open(filename, "w") as f:
        for log in logs:
            f.write(log + "\n")

    print(f"✅ Generated {NUM_NORMAL_LOGS} normal logs and {NUM_ANOMALOUS_LOGS} anomalous logs into {filename}")

# Execute
if __name__ == "__main__":
    generate_logs()
