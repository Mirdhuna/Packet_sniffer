class Packet:
    def __init__(self, data: dict):
        self.timestamp = data.get("timestamp")
        self.src_ip = data.get("src_ip")
        self.dest_ip = data.get("dst_ip")
        self.protocol = data.get("protocol")
        self.src_port = data.get("src_port")
        self.dest_port = data.get("dst_port")
        self.length = data.get("length")
        self.flags = data.get("flags")

    def is_valid(self):
        return self.src_ip is not None and self.dest_ip is not None
