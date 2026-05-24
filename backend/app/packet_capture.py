from scapy.all import sniff
from app.packet_parser import parse_packet

captured_packets = []
is_capturing = False


def process_packet(packet):

    parsed_packet = parse_packet(packet)

    if parsed_packet:
        captured_packets.append(parsed_packet)

        print(parsed_packet)


def start_sniffing():
    global is_capturing

    if is_capturing:
        return

    is_capturing = True

    sniff(
        prn=process_packet,
        store=False
    )