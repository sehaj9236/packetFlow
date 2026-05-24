from datetime import datetime
import ipaddress

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

from app.process_detector import get_process_from_port
from app.dns_cache import add_dns_mapping, get_domain_from_ip
from app.app_classifier import classify_application


FLOW_CACHE = {}


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False


def get_flow_key(packet_data):
    ip1 = packet_data["src_ip"]
    ip2 = packet_data["dst_ip"]

    port1 = packet_data["src_port"]
    port2 = packet_data["dst_port"]

    protocol = packet_data["protocol"]

    return tuple(sorted([
        (ip1, port1),
        (ip2, port2)
    ])) + (protocol,)


def save_dns_mapping(packet):
    if not packet.haslayer(DNS):
        return

    dns_layer = packet[DNS]

    if dns_layer.qr != 1:
        return

    try:
        queried_domain = dns_layer.qd.qname.decode().rstrip(".")

        for i in range(dns_layer.ancount):
            answer = dns_layer.an[i]

            if isinstance(answer, DNSRR):
                resolved_ip = answer.rdata

                if isinstance(resolved_ip, str):
                    add_dns_mapping(resolved_ip, queried_domain)

    except:
        pass


def decode_dns(packet):
    if not packet.haslayer(DNS):
        return None

    dns_layer = packet[DNS]

    try:
        decoded = {
            "type": "DNS Response" if dns_layer.qr == 1 else "DNS Query",
            "query": None,
            "answers": []
        }

        if dns_layer.qd and isinstance(dns_layer.qd, DNSQR):
            decoded["query"] = dns_layer.qd.qname.decode().rstrip(".")

        if dns_layer.qr == 1:
            for i in range(dns_layer.ancount):
                answer = dns_layer.an[i]

                if isinstance(answer, DNSRR):
                    decoded["answers"].append(str(answer.rdata))

        return decoded

    except:
        return None


def decode_http(packet):
    if not packet.haslayer(Raw):
        return None

    try:
        payload = packet[Raw].load.decode(
            "utf-8",
            errors="ignore"
        )

        if not (
            payload.startswith("GET")
            or payload.startswith("POST")
            or payload.startswith("PUT")
            or payload.startswith("DELETE")
            or payload.startswith("HEAD")
            or payload.startswith("HTTP")
        ):
            return None

        lines = payload.split("\r\n")

        decoded = {
            "type": "HTTP",
            "request_line": lines[0] if lines else None,
            "host": None,
            "user_agent": None
        }

        for line in lines:
            lower = line.lower()

            if lower.startswith("host:"):
                decoded["host"] = line.split(":", 1)[1].strip()

            elif lower.startswith("user-agent:"):
                decoded["user_agent"] = line.split(":", 1)[1].strip()

        return decoded

    except:
        return None


def decode_packet_details(packet):
    decoded = {
        "ip": {},
        "transport": {},
        "application_layer": None
    }

    if IP in packet:
        decoded["ip"] = {
            "version": packet[IP].version,
            "ttl": packet[IP].ttl,
            "flags": str(packet[IP].flags),
            "id": packet[IP].id
        }

    if TCP in packet:
        decoded["transport"] = {
            "type": "TCP",
            "seq": packet[TCP].seq,
            "ack": packet[TCP].ack,
            "flags": str(packet[TCP].flags),
            "window": packet[TCP].window
        }

    elif UDP in packet:
        decoded["transport"] = {
            "type": "UDP",
            "length": packet[UDP].len
        }

    elif ICMP in packet:
        decoded["transport"] = {
            "type": "ICMP",
            "icmp_type": packet[ICMP].type,
            "icmp_code": packet[ICMP].code
        }

    dns_decoded = decode_dns(packet)

    if dns_decoded:
        decoded["application_layer"] = dns_decoded
        return decoded

    http_decoded = decode_http(packet)

    if http_decoded:
        decoded["application_layer"] = http_decoded
        return decoded

    return decoded


def parse_packet(packet):
    if IP not in packet:
        return None

    save_dns_mapping(packet)

    parsed_data = {
        "timestamp": datetime.now().isoformat(),

        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,

        "packet_size": len(packet),
        "protocol": "OTHER",

        "src_port": None,
        "dst_port": None,

        "application": "Unknown",
        "detected_service": "Unknown",

        "decoded": decode_packet_details(packet)
    }

    if TCP in packet:
        parsed_data["protocol"] = "TCP"
        parsed_data["src_port"] = packet[TCP].sport
        parsed_data["dst_port"] = packet[TCP].dport

    elif UDP in packet:
        parsed_data["protocol"] = "UDP"
        parsed_data["src_port"] = packet[UDP].sport
        parsed_data["dst_port"] = packet[UDP].dport

    elif ICMP in packet:
        parsed_data["protocol"] = "ICMP"

    if parsed_data["src_port"]:
        parsed_data["application"] = get_process_from_port(
            parsed_data["src_port"]
        )

    flow_key = get_flow_key(parsed_data)

    if flow_key in FLOW_CACHE:
        parsed_data["detected_service"] = FLOW_CACHE[flow_key]
        return parsed_data

    hostname = "Unknown"
    dst_ip = parsed_data["dst_ip"]

    if not is_private_ip(dst_ip):
        hostname = get_domain_from_ip(dst_ip)

    parsed_data["detected_service"] = classify_application(
        hostname,
        parsed_data["application"]
    )

    if parsed_data["detected_service"] != "Unknown":
        FLOW_CACHE[flow_key] = parsed_data["detected_service"]

    return parsed_data