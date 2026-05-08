from flask import Flask, render_template, request
import socket
import time

app = Flask(__name__)


# ---------------- RISK LEVEL FUNCTION ---------------- #

def get_risk(port):

    high_risk = [21, 23, 445, 3389]
    medium_risk = [22, 80, 139]

    if port in high_risk:
        return "HIGH"

    elif port in medium_risk:
        return "MEDIUM"

    else:
        return "LOW"


# ---------------- PORT SCANNER FUNCTION ---------------- #

def scan_ports(target):

    ports = [
        20, 21, 22, 23, 25,
        53, 67, 68, 69, 80,
        110, 119, 123, 135,
        137, 138, 139, 143,
        161, 389, 443, 445,
        465, 514, 587, 636,
        993, 995, 1433, 1521,
        1723, 3306, 3389,
        5432, 5900, 8080
    ]

    results = []

    start_time = time.time()

    for port in ports:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        try:
            service = socket.getservbyport(port, "tcp")
        except:
            service = "Unknown"

        risk = get_risk(port)

        if result == 0:
            results.append((port, service, "OPEN", risk))
        else:
            results.append((port, service, "CLOSED", risk))

        sock.close()

    end_time = time.time()

    scan_time = round(end_time - start_time, 2)

    return results, scan_time


# ---------------- FLASK ROUTE ---------------- #

@app.route('/', methods=['GET', 'POST'])

def index():

    results = []
    scan_time = None

    if request.method == 'POST':
