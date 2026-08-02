def apply_filter(packet, filters):
    if not filters:
        return True

    if "protocol" in filters and packet["protocol"] != filters["protocol"]:
        return False

    if "src_ip" in filters and packet["src_ip"] != filters["src_ip"]:
        return False

    if "dst_ip" in filters and packet["dst_ip"] != filters["dst_ip"]:
        return False

    return True
