# Packet Sniffer and Network Traffic Analyzer

## Overview

This project is a **Python-based Packet Sniffer and Network Traffic Analyzer** designed to capture, parse, filter, and analyze network packets. It provides an interactive interface for monitoring network communication, inspecting packet details, applying filters, and visualizing captured traffic.

The application demonstrates fundamental concepts of **Computer Networks**, **Packet Analysis**, and **Network Security**, making it suitable for educational purposes and practical learning.

---

## Features

* Capture and analyze network packets
* Parse packet information into a structured format
* Filter packets based on different criteria
* Save captured packets in JSON format
* Load previously captured packet data
* Visualize packet statistics
* Interactive graphical user interface
* Analyze sample attack packets for educational purposes

---

## Technologies Used

* **Language:** Python
* **GUI:** Tkinter
* **Data Format:** JSON
* **Libraries:** Python Standard Library (and networking libraries if installed)

---

## Project Structure

```text
.
├── analyzer.py
├── attack_demo_packets.json
├── json_loader.py
├── json_writer.py
├── main.py
├── packet.py
├── packet_filter.py
├── packet_parser.py
├── packet_sniffer.py
├── packets.json
├── sniffer.py
├── ui.py
├── visualizer.py
└── README.md
```

---

## Modules

### Packet Sniffer

Captures packets from the network interface for analysis.

### Packet Parser

Extracts important information such as:

* Source IP Address
* Destination IP Address
* Protocol
* Port Numbers
* Packet Size

### Packet Filter

Allows filtering packets based on:

* Protocol
* Source IP
* Destination IP
* Port Numbers

### Analyzer

Processes captured packets and generates useful insights about network traffic.

### JSON Reader & Writer

Stores captured packets in JSON format and reloads them for future analysis.

### Visualizer

Displays packet statistics and network activity in a user-friendly format.

---

## How to Run

1. Clone the repository.

```bash
git clone https://github.com/Mirdhuna/Packet_sniffer.git
```

2. Navigate to the project directory.

```bash
cd Packet_sniffer
```

3. Install any required dependencies.

```bash
pip install -r requirements.txt
```

*(If your project does not include a `requirements.txt`, install any required libraries manually.)*

4. Run the application.

```bash
python main.py
```

---

## Learning Outcomes

This project helped in understanding:

* Packet sniffing techniques
* Network protocols
* Packet parsing
* Network traffic analysis
* JSON data handling
* GUI development using Tkinter
* Python object-oriented programming
* Basic concepts of cybersecurity and network monitoring

---

## Future Enhancements

* Real-time packet capture using Scapy
* Live packet visualization dashboard
* Protocol-wise traffic graphs
* Export analysis reports
* Intrusion detection rules
* Packet search functionality
* Dark mode interface
* Support for PCAP file import and export

---

## Disclaimer

This project is intended **only for educational and research purposes**. It should be used only on networks where you have proper authorization to monitor traffic. Unauthorized packet sniffing may violate privacy policies and local laws.

---

## Author

**Mirdhuna Nandhakumar**

M.Sc. Theoretical Computer Science

---

## License

This project is intended for educational and academic purposes.
