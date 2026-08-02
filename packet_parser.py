from scapy.layers.inet import IP, TCP, UDP, ICMP

def parse_packet(packet):
    parsed = {
        "timestamp": str(packet.time),
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "length": len(packet),
        "flags": None
    }

    if packet.haslayer(IP):
        ip = packet[IP]
        parsed["src_ip"] = ip.src
        parsed["dst_ip"] = ip.dst

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            parsed["protocol"] = "TCP"
            parsed["src_port"] = tcp.sport
            parsed["dst_port"] = tcp.dport
            parsed["flags"] = str(tcp.flags)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            parsed["protocol"] = "UDP"
            parsed["src_port"] = udp.sport
            parsed["dst_port"] = udp.dport

        elif packet.haslayer(ICMP):
            parsed["protocol"] = "ICMP"

    return parsed
