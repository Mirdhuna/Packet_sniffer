import json
from packet import Packet

class Json_packet_loader:
    def __init__(self, file_path):
        self.file_path = file_path

    def stream(self):
        with open(self.file_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                packet = Packet(data)

                if packet.is_valid():
                    yield packet
