"""
Generates a synthetic security log dataset for the threat detection project.

The dataset intentionally includes:
- normal background activity
- a brute-force login attack
- a port-scanning attack
- suspicious SQL-injection-style web requests

Each row also has a 'true_label' column (normal / attack type) so we can
evaluate our detection rules and ML model later. In a real SOC, logs do NOT
come pre-labeled like this — we add labels only because this is a learning
project and we need a way to check our own work.
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

OUTPUT_PATH = Path("data/raw/synthetic_logs.csv")

FIELDNAMES = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "event_type",
    "username",
    "login_status",
    "http_method",
    "url_or_path",
    "response_status_code",
    "bytes_transferred",
    "true_label",
]

NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin"]
NORMAL_PATHS = ["/home", "/products", "/about", "/contact", "/login", "/cart"]
SERVER_IP = "10.0.0.5"


def random_ip(prefix: str = "192.168.1") -> str:
    """Creates a plausible-looking private IP address for our fake network."""
    return f"{prefix}.{random.randint(2, 254)}"


def make_row(
    timestamp: datetime,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    protocol: str,
    event_type: str,
    username: str,
    login_status: str,
    http_method: str,
    url_or_path: str,
    response_status_code: int,
    bytes_transferred: int,
    true_label: str,
) -> dict:
    """Builds one log row as a dictionary matching FIELDNAMES."""
    return {
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "event_type": event_type,
        "username": username,
        "login_status": login_status,
        "http_method": http_method,
        "url_or_path": url_or_path,
        "response_status_code": response_status_code,
        "bytes_transferred": bytes_transferred,
        "true_label": true_label,
    }


def generate_normal_activity(start_time: datetime, count: int) -> list[dict]:
    """Creates ordinary, non-suspicious login and browsing activity."""
    rows = []
    for i in range(count):
        ts = start_time + timedelta(seconds=random.randint(0, 3600))
        user = random.choice(NORMAL_USERS)
        ip = random_ip()

        # Occasionally a normal failed login (mistyped password), mostly success
        login_status = "success" if random.random() > 0.1 else "failed"

        rows.append(
            make_row(
                timestamp=ts,
                source_ip=ip,
                destination_ip=SERVER_IP,
                source_port=random.randint(1024, 65000),
                destination_port=443,
                protocol="TCP",
                event_type="login",
                username=user,
                login_status=login_status,
                http_method="GET",
                url_or_path=random.choice(NORMAL_PATHS),
                response_status_code=200,
                bytes_transferred=random.randint(200, 5000),
                true_label="normal",
            )
        )
    return rows


def generate_brute_force(start_time: datetime) -> list[dict]:
    """
    Simulates one attacker IP repeatedly failing to log in as the same
    username within a short time window (classic brute-force pattern).
    """
    attacker_ip = random_ip(prefix="203.0.113")
    target_user = "admin"
    rows = []
    for i in range(25):  # 25 failed attempts in under 2 minutes
        ts = start_time + timedelta(seconds=i * 4)
        rows.append(
            make_row(
                timestamp=ts,
                source_ip=attacker_ip,
                destination_ip=SERVER_IP,
                source_port=random.randint(1024, 65000),
                destination_port=443,
                protocol="TCP",
                event_type="login",
                username=target_user,
                login_status="failed",
                http_method="POST",
                url_or_path="/login",
                response_status_code=401,
                bytes_transferred=random.randint(100, 300),
                true_label="brute_force",
            )
        )
    return rows


def generate_port_scan(start_time: datetime) -> list[dict]:
    """
    Simulates one attacker IP connecting to many different destination
    ports on the same target within a short time window.
    """
    attacker_ip = random_ip(prefix="198.51.100")
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
    rows = []
    for i, port in enumerate(ports_to_scan):
        ts = start_time + timedelta(seconds=i * 2)
        rows.append(
            make_row(
                timestamp=ts,
                source_ip=attacker_ip,
                destination_ip=SERVER_IP,
                source_port=random.randint(1024, 65000),
                destination_port=port,
                protocol="TCP",
                event_type="connection",
                username="",
                login_status="",
                http_method="",
                url_or_path="",
                response_status_code=0,
                bytes_transferred=random.randint(0, 100),
                true_label="port_scan",
            )
        )
    return rows


def generate_sql_injection(start_time: datetime) -> list[dict]:
    """
    Simulates web requests containing common SQL-injection-style patterns
    in the URL/query parameters.
    """
    attacker_ip = random_ip(prefix="203.0.113")
    suspicious_paths = [
        "/products?id=1' OR 1=1--",
        "/search?q=UNION SELECT username,password FROM users",
        "/login?user=admin' OR SLEEP(5)--",
        "/products?id=1 AND 1=1 UNION SELECT NULL,information_schema.tables--",
    ]
    rows = []
    for i, path in enumerate(suspicious_paths):
        ts = start_time + timedelta(seconds=i * 3)
        rows.append(
            make_row(
                timestamp=ts,
                source_ip=attacker_ip,
                destination_ip=SERVER_IP,
                source_port=random.randint(1024, 65000),
                destination_port=443,
                protocol="TCP",
                event_type="http_request",
                username="",
                login_status="",
                http_method="GET",
                url_or_path=path,
                response_status_code=random.choice([200, 500]),
                bytes_transferred=random.randint(200, 2000),
                true_label="sql_injection",
            )
        )
    return rows


def main() -> None:
    random.seed(42)  # makes the "random" data reproducible for everyone
    start_time = datetime(2025, 1, 1, 9, 0, 0)

    all_rows = []
    all_rows += generate_normal_activity(start_time, count=200)
    all_rows += generate_brute_force(start_time + timedelta(minutes=15))
    all_rows += generate_port_scan(start_time + timedelta(minutes=30))
    all_rows += generate_sql_injection(start_time + timedelta(minutes=45))

    all_rows.sort(key=lambda r: r["timestamp"])

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"Generated {len(all_rows)} log rows -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()