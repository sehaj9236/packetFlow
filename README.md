# PacketFlow Analytics

## Real-Time Network Traffic Intelligence & Anomaly Detection Platform

PacketFlow Analytics is a real-time network traffic monitoring and analytics platform that captures live packets, performs deep traffic analysis, identifies applications/services, detects anomalous behavior using Machine Learning, and visualizes network intelligence metrics.

The platform combines:
- packet sniffing
- traffic analytics
- DNS intelligence
- process-level monitoring
- ML anomaly detection
- observability metrics

into a unified analytics engine.

---

# Features

## Real-Time Packet Capture
- Live packet sniffing using Scapy
- TCP/UDP protocol parsing
- Source/Destination IP tracking
- Port analysis
- Packet size monitoring

---

## Application & Service Detection
- Local process detection using `psutil`
- DNS intelligence caching
- Domain-based traffic classification

---

## Advanced Analytics APIs
- Top Source IPs
- Top Destination IPs
- Top Applications
- Top Services
- Top Ports
- Protocol Distribution
- Bandwidth Usage
- Throughput Analysis
- Traffic Volume Analysis

---

## Machine Learning Anomaly Detection

Implemented:
- Isolation Forest based anomaly detection

ML Features:
- Packet size analysis
- Port behavior analysis
- Unknown traffic analysis
- Protocol behavior analysis

Generated Metrics:
- Traffic Anomaly Score
- Anomaly Rate
- Network Status Classification

---

# Tech Stack

## Backend
- Python
- FastAPI
- Scapy
- psutil
- Scikit-learn
- NumPy

## Frontend
- Next.js
- Tailwind CSS
- Recharts
- Axios

## Machine Learning
- Isolation Forest

---

# System Architecture

```text
Packet Capture Engine
        ↓
Packet Parser
        ↓
DNS Intelligence Layer
        ↓
Process Detection Layer
        ↓
Service Classification Engine
        ↓
Analytics Engine
        ↓
ML Anomaly Detection
        ↓
REST APIs
        ↓
Frontend Dashboard
```

---

# Project Structure

```text
packetflow-analytics/
│
├── backend/
│   └── app/
│       ├── main.py
│       ├── packet_capture.py
│       ├── packet_parser.py
│       ├── process_detector.py
│       ├── dns_cache.py
│       ├── app_classifier.py
│       ├── dns_resolver.py
│       ├── ml_anomaly_detector.py
│
├── frontend/
│   ├── app/
│   ├── components/
│   └── services/
│
└── README.md
```

---

# APIs

## Packet APIs

### Start Packet Capture

```http
POST /capture/start
```

### Get Recent Packets

```http
GET /packets
```

---

## Analytics APIs

### Summary Analytics

```http
GET /analytics/summary
```

### Top Source IPs

```http
GET /analytics/top-source-ips
```

### Top Destination IPs

```http
GET /analytics/top-destination-ips
```

### Top Ports

```http
GET /analytics/top-ports
```

### Top Applications

```http
GET /analytics/top-applications
```

### Top Services

```http
GET /analytics/top-services
```

### Top Hostnames

```http
GET /analytics/top-hostnames
```

### Bandwidth Analytics

```http
GET /analytics/top-bandwidth-services
```

---

## ML APIs

### Traffic Anomaly Score

```http
GET /ml/traffic-anomaly-score
```

### ML Anomaly Detection

```http
GET /ml/anomalies
```

---

# Installation

## Clone Repository

```bash
git clone <repo-url>
cd packetflow-analytics
```

---

# Backend Setup

## Create Virtual Environment

```bash
cd backend

python -m venv venv
```

Activate:

### Windows

```bash
venv\Scripts\activate
```

### Linux/Mac

```bash
source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Install Npcap (Windows)

Download:
https://npcap.com/#download

Important:
Enable:

```text
Install Npcap in WinPcap API-compatible Mode
```

---

## Run Backend

```bash
python -m uvicorn app.main:app --reload
```

Swagger Docs:

```text
http://127.0.0.1:8000/docs
```

---

# Frontend Setup

```bash
cd frontend

npm install

npm run dev
```

Frontend:

```text
http://localhost:3000
```

---

# Example Packet

```json
{
  "timestamp": "2026-05-23T17:29:07.538042",
  "src_ip": "162.159.133.234",
  "dst_ip": "192.168.1.36",
  "packet_size": 329,
  "protocol": "TCP",
  "src_port": 443,
  "dst_port": 54115,
  "application": "chrome.exe",
  "hostname": "youtube.com",
  "detected_service": "YouTube"
}
```

---

# Example Analytics Response

```json
{
  "total_packets": 25643,
  "total_data_bytes": 18239421,
  "protocol_distribution": {
    "TCP": 20114,
    "UDP": 5529
  }
}
```

---

# Example ML Output

```json
{
  "traffic_anomaly_score": 18.4,
  "status": "NORMAL",
  "anomaly_rate_percent": 3.1,
  "unknown_traffic_percent": 8.2
}
```

---

# Future Improvements

## Planned Features
- WebSocket real-time streaming
- Packet loss estimation
- Latency estimation
- Jitter analysis
- Threat intelligence integration
- GeoIP mapping
- Attack heatmaps
- PCAP upload analysis
- Traffic forecasting using LSTMs
- Role-based dashboards
- SIEM integration

---

# Use Cases

- Network Monitoring
- Traffic Analytics
- Security Observability
- Anomaly Detection
- Application Traffic Intelligence
- Infrastructure Monitoring
- ML-based Traffic Analysis

---

# Resume Description

Built a real-time network traffic intelligence and anomaly detection platform using FastAPI, Scapy, and Isolation Forest ML models. Implemented packet capture, DNS intelligence caching, process-level traffic attribution, service classification, and analytics APIs for monitoring network behavior, bandwidth usage, and anomalous traffic patterns.

---

# License

MIT License
