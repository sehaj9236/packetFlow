import numpy as np
from sklearn.ensemble import IsolationForest


KNOWN_NOISY_SERVICES = {
    "Discord",
    "Steam",
    "Brave",
    "Chrome",
    "Spotify",
    "YouTube"
}

KNOWN_NOISY_APPS = {
    "Discord.exe",
    "steam.exe",
    "brave.exe",
    "chrome.exe",
    "Spotify.exe"
}


def detect_anomalies(packets):
    if len(packets) < 50:
        return {
            "message": "Need at least 50 packets for ML anomaly detection",
            "anomalies": []
        }

    features = []

    for packet in packets:
        features.append([
            packet.get("packet_size", 0),
            packet.get("src_port") or 0,
            packet.get("dst_port") or 0,
            1 if packet.get("protocol") == "TCP" else 0,
            1 if packet.get("protocol") == "UDP" else 0,
            1 if packet.get("detected_service") == "Unknown" else 0,
        ])

    X = np.array(features)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.03,
        random_state=42
    )

    predictions = model.fit_predict(X)
    scores = model.decision_function(X)

    anomalies = []

    for i, prediction in enumerate(predictions):
        if prediction == -1:

            service = packets[i].get("detected_service", "Unknown")
            application = packets[i].get("application", "Unknown")

            if service in KNOWN_NOISY_SERVICES:
                continue

            if application in KNOWN_NOISY_APPS:
                continue

            anomaly_packet = packets[i].copy()
            anomaly_packet["anomaly_score"] = float(scores[i])
            anomaly_packet["reason"] = "Unusual packet pattern detected by Isolation Forest"
            anomalies.append(anomaly_packet)

    return {
        "total_packets_analyzed": len(packets),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies[-50:]
    }