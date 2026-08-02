from scapy.all import sniff
from packet_parser import parse_packet
from packet_filter import apply_filter
from json_writer import write_packet_to_json

def packet_callback(packet, filters):
    parsed_data = parse_packet(packet)

    if apply_filter(parsed_data, filters):
        print(parsed_data)
        write_packet_to_json(parsed_data)

def run_sniffer(interface=None, filters=None,timeout=20):
    print("[*] Starting packet sniffer... Press Ctrl+C to stop")

    sniff(
        iface=interface,
        prn=lambda pkt: packet_callback(pkt, filters),
        store=False,
        timeout=timeout   
    )
