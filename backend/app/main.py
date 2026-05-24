from collections import Counter
from fastapi import FastAPI
from app.packet_capture import start_sniffing, captured_packets, is_capturing
import threading
from app.ml_anomaly_detector import detect_anomalies
from datetime import datetime
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.get("/")
def home():
    return {
        "message": "PacketFlow Analytics Running"
    }

@app.post("/capture/start")
def start_capture():

    if is_capturing:
        return {
            "message": "Packet capture already running"
        }

    capture_thread = threading.Thread(
        target=start_sniffing
    )

    capture_thread.daemon = True
    capture_thread.start()

    return {
        "message": "Packet capture started"
    }
@app.get("/capture/status")
def capture_status():
    return {
        "is_capturing": is_capturing
    }

@app.get("/packets")
def get_packets():

    return captured_packets[-50:]

@app.get("/analytics/summary")
def get_summary():

    total_packets = len(captured_packets)

    total_data = sum(
        packet["packet_size"]
        for packet in captured_packets
    )

    protocol_distribution = {}

    for packet in captured_packets:

        protocol = packet["protocol"]

        protocol_distribution[protocol] = (
            protocol_distribution.get(protocol, 0) + 1
        )

    return {
        "total_packets": total_packets,
        "total_data_bytes": total_data,
        "protocol_distribution": protocol_distribution
    }
@app.get("/analytics/top-ips")
def top_ips():
    ip_counter = Counter()

    for packet in captured_packets:
        ip_counter[packet["src_ip"]] += 1
        ip_counter[packet["dst_ip"]] += 1

    return {"top_ips": ip_counter.most_common(10)}


@app.get("/analytics/top-ports")
def top_ports():
    port_counter = Counter()

    for packet in captured_packets:
        if packet["src_port"]:
            port_counter[packet["src_port"]] += 1

        if packet["dst_port"]:
            port_counter[packet["dst_port"]] += 1

    return {"top_ports": port_counter.most_common(10)}


@app.get("/analytics/protocols")
def protocols():
    protocol_counter = Counter()

    for packet in captured_packets:
        protocol_counter[packet["protocol"]] += 1

    return {"protocols": protocol_counter}

@app.get("/analytics/top-source-ips")
def top_source_ips():
    source_counter = Counter()

    for packet in captured_packets:
        source_counter[packet["src_ip"]] += 1

    return {
        "top_source_ips": source_counter.most_common(10)
    }


@app.get("/analytics/top-destination-ips")
def top_destination_ips():
    destination_counter = Counter()

    for packet in captured_packets:
        destination_counter[packet["dst_ip"]] += 1

    return {
        "top_destination_ips": destination_counter.most_common(10)
    }

@app.get("/analytics/top-services")
def top_services():
    service_counter = Counter()

    for packet in captured_packets:
        service_counter[packet["detected_service"]] += 1

    return {
        "top_services": service_counter.most_common(10)
    }

@app.get("/analytics/top-applications")
def top_applications():
    app_counter = Counter()

    for packet in captured_packets:
        app_counter[packet["application"]] += 1

    return {
        "top_applications": app_counter.most_common(10)
    }




@app.get("/packets/filter")
def filter_packets(protocol: str = None, service: str = None):
    results = captured_packets

    if protocol:
        results = [
            packet for packet in results
            if packet["protocol"].lower() == protocol.lower()
        ]

    if service:
        results = [
            packet for packet in results
            if packet["detected_service"].lower() == service.lower()
        ]

    return results[-100:]


import csv
from fastapi.responses import FileResponse

@app.get("/export/csv")
def export_csv():
    filename = "packets_export.csv"

    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=captured_packets[0].keys())
        writer.writeheader()
        writer.writerows(captured_packets)

    return FileResponse(filename, media_type="text/csv", filename=filename)

@app.get("/ml/anomalies")
def ml_anomalies():
    return detect_anomalies(captured_packets)

@app.get("/analytics/top-bandwidth-services")
def top_bandwidth_services():

    bandwidth = {}

    for packet in captured_packets:

        service = packet["detected_service"]

        if service == "Unknown":
            continue

        bandwidth[service] = (
            bandwidth.get(service, 0)
            + packet["packet_size"]
        )

    formatted = []

    for service, bytes_used in bandwidth.items():

        mb_used = round(
            bytes_used / (1024 * 1024),
            2
        )

        formatted.append({
            "service": service,
            "mb_used": mb_used
        })

    formatted.sort(
        key=lambda x: x["mb_used"],
        reverse=True
    )

    return {
        "top_bandwidth_services": formatted
    }

@app.get("/analytics/network-health")
def network_health():

    if len(captured_packets) < 10:
        return {
            "health": "INSUFFICIENT_DATA",
            "score": 0,
            "load": "UNKNOWN",
            "message": "Need more packets to calculate network health"
        }

    total_packets = len(captured_packets)
    total_bytes = sum(packet["packet_size"] for packet in captured_packets)

    first_time = datetime.fromisoformat(captured_packets[0]["timestamp"])
    last_time = datetime.fromisoformat(captured_packets[-1]["timestamp"])

    duration_seconds = max(
        (last_time - first_time).total_seconds(),
        1
    )

    packets_per_second = total_packets / duration_seconds
    throughput_mbps = (total_bytes * 8) / duration_seconds / 1_000_000
    avg_packet_size = total_bytes / total_packets

    udp_count = sum(
        1 for packet in captured_packets
        if packet["protocol"] == "UDP"
    )

    tcp_count = sum(
        1 for packet in captured_packets
        if packet["protocol"] == "TCP"
    )

    unknown_count = sum(
        1 for packet in captured_packets
        if packet["detected_service"] == "Unknown"
    )

    anomaly_result = detect_anomalies(captured_packets)
    anomaly_count = anomaly_result.get("anomaly_count", 0)

    udp_ratio = udp_count / total_packets
    tcp_ratio = tcp_count / total_packets
    unknown_ratio = unknown_count / total_packets
    anomaly_ratio = anomaly_count / total_packets

    # -------------------------
    # LOAD SCORE
    # -------------------------

    if throughput_mbps > 80 or packets_per_second > 800:
        load = "VERY_HIGH"
    elif throughput_mbps > 30 or packets_per_second > 400:
        load = "HIGH"
    elif throughput_mbps > 10 or packets_per_second > 150:
        load = "MODERATE"
    else:
        load = "LOW"

    # -------------------------
    # HEALTH SCORE
    # -------------------------

    score = 100
    reasons = []
    load_notes = []

    if load in ["HIGH", "VERY_HIGH"]:
        load_notes.append("Heavy network usage detected")
    elif load == "MODERATE":
        load_notes.append("Moderate network usage detected")

    # Penalize real risk, not normal traffic volume
    if anomaly_ratio > 0.10:
        score -= 30
        reasons.append("High anomaly ratio detected")

    elif anomaly_ratio > 0.05:
        score -= 18
        reasons.append("Moderate anomaly ratio detected")

    elif anomaly_count > 0:
        score -= 5
        reasons.append("Small number of anomalous packets detected")

    if unknown_ratio > 0.80:
        score -= 15
        reasons.append("Very high unidentified traffic ratio")

    elif unknown_ratio > 0.60:
        score -= 8
        reasons.append("High unidentified traffic ratio")

    if udp_ratio > 0.95:
        score -= 10
        reasons.append("Extremely high UDP dominance detected")

    if avg_packet_size > 1450:
        score -= 5
        reasons.append("Very large average packet size detected")

    score = max(score, 0)

    if score >= 85:
        health = "GOOD"
    elif score >= 70:
        health = "MODERATE"
    elif score >= 50:
        health = "POOR"
    else:
        health = "CRITICAL"

    final_reasons = []

    if reasons:
        final_reasons.extend(reasons)
    else:
        final_reasons.append("No major network quality risks detected")

    final_reasons.extend(load_notes)

    return {
        "health": health,
        "score": round(score, 2),
        "load": load,
        "metrics": {
            "total_packets": total_packets,
            "duration_seconds": round(duration_seconds, 2),
            "packets_per_second": round(packets_per_second, 2),
            "throughput_mbps": round(throughput_mbps, 2),
            "avg_packet_size": round(avg_packet_size, 2),
            "tcp_ratio": round(tcp_ratio, 2),
            "udp_ratio": round(udp_ratio, 2),
            "unknown_ratio": round(unknown_ratio, 2),
            "anomaly_count": anomaly_count,
            "anomaly_ratio": round(anomaly_ratio, 4)
        },
        "reasons": final_reasons
    }
@app.get("/ml/traffic-anomaly-score")
def traffic_anomaly_score():

    result = detect_anomalies(captured_packets)

    total_packets = result["total_packets_analyzed"]
    anomaly_count = result["anomaly_count"]

    if total_packets == 0:
        return {
            "traffic_anomaly_score": 0,
            "status": "NORMAL"
        }

    anomaly_rate = anomaly_count / total_packets

    unknown_traffic = sum(
        1 for p in captured_packets
        if p["detected_service"] == "Unknown"
    )

    unknown_ratio = unknown_traffic / total_packets

    raw_score = (
    anomaly_rate * 0.8
    +
    unknown_ratio * 0.2
   )

    score = round(min(raw_score * 100, 100), )

    status = "NORMAL"

    if score > 70:
        status = "CRITICAL"

    elif score > 40:
        status = "HIGH"

    elif score > 20:
        status = "MODERATE"

    return {
        "traffic_anomaly_score": score,
        "status": status,
        "anomaly_rate_percent": round(anomaly_rate * 100, 2),
        "unknown_traffic_percent": round(unknown_ratio * 100, 2)
    }