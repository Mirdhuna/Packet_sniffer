import json
import os

FILE = "packets.json"

def write_packet_to_json(packet):
    data = []

    if os.path.exists(FILE):
        with open(FILE, "r") as f:
            try:
                data = json.load(f)
            except:
                data = []

    data.append(packet)

    with open(FILE, "w") as f:
        json.dump(data, f, indent=2)