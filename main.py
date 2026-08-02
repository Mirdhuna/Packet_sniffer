from packet_sniffer import run_sniffer
from analyzer import Packet_analyzer
from json_loader import Json_packet_loader
from visualizer import Visualizer

def start_capture():
    print("[*] Capturing packets for 20 seconds...\n")
    
    # 🔥 Run sniffer with timeout (must be implemented in packet_sniffer.py)
    run_sniffer(timeout=20)

    print("\n[*] Capture finished.\n")


def start_analysis():
    analyzer = Packet_analyzer()
    loader = Json_packet_loader("packets.json")

    print("[*] Starting Analysis...\n")

    for packet in loader.stream():
        analyzer.process_packet(packet)

    analyzer.print_summary()

    visualizer = Visualizer(analyzer)
    visualizer.plot_protocol_distribution()
    visualizer.plot_top_ips()
    visualizer.plot_top_ports()


if __name__ == "__main__":
    # Clear old data
    open("packets.json", "w").close()

    # Step 1: Capture
    start_capture()

    # Step 2: Analyze
    start_analysis()