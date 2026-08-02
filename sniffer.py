from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime
from packet import Packet

def parse_packet(packet):
    parsed = {
        "timestamp": str(datetime.now()),
        "src_ip": None,
        "dest_ip": None,
        "protocol": None,
        "src_port": None,
        "dest_port": None,
        "flags": None
    }

    if packet.haslayer(IP):
        ip = packet[IP]
        parsed["src_ip"] = ip.src
        parsed["dest_ip"] = ip.dst

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            parsed["protocol"] = "TCP"
            parsed["src_port"] = tcp.sport
            parsed["dest_port"] = tcp.dport
            parsed["flags"] = str(tcp.flags)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            parsed["protocol"] = "UDP"
            parsed["src_port"] = udp.sport
            parsed["dest_port"] = udp.dport

        elif packet.haslayer(ICMP):
            parsed["protocol"] = "ICMP"

    return Packet(parsed)


def packet_stream():
    while True:
        packets = sniff(count=10)
        for pkt in packets:
            packet = parse_packet(pkt)
            if packet.is_valid():
                yield packet
