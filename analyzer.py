from collections import defaultdict
from datetime import datetime

# ──────────────────────────────────────────────
#  KNOWN-GOOD IP RANGES (whitelisted)
#  Traffic from/to these will never raise alerts.
#  These are major CDN / cloud / DNS providers
#  that generate high-volume but totally normal traffic.
# ──────────────────────────────────────────────
WHITELIST_PREFIXES = (
    "142.251.",   # Google services  (Gmail, Drive, YouTube, Meet)
    "172.217.",   # Google services
    "216.58.",    # Google services
    "34.120.",    # Google Cloud / Cloudflare CDN
    "104.18.",    # Cloudflare
    "104.16.",    # Cloudflare
    "151.101.",   # Fastly CDN
    "185.125.",   # Ubuntu / Canonical
    "192.168.",   # Private LAN — your own network
    "10.",        # Private LAN
    "172.16.",    # Private LAN
    "172.17.",    # Docker / private
    "172.18.",    # Docker / private
    "224.0.",     # Multicast (mDNS, SSDP — always normal)
    "239.255.",   # Multicast (SSDP)
)

# ──────────────────────────────────────────────
#  SENSITIVE PORTS
#  Brute-force detection ONLY fires on these.
#  Port 443 removed — it is normal HTTPS, not an attack surface.
# ──────────────────────────────────────────────
SENSITIVE_PORTS = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    3389,  # RDP (Windows Remote Desktop)
    5900,  # VNC
}

# ──────────────────────────────────────────────
#  NORMAL PORTS
#  Port scan detection ignores these ports —
#  hitting them doesn't count as scanning.
# ──────────────────────────────────────────────
NORMAL_PORTS = {
    80, 443, 53, 5353, 5355, 1900, 123, 67, 68
}


def is_whitelisted(ip):
    """Return True if the IP belongs to a known-good provider."""
    if ip is None:
        return False
    for prefix in WHITELIST_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False


class Packet_analyzer:
    def __init__(self, mode="both"):
        self.mode = mode
        self.total_packets = 0

        # Basic stats
        self.protocol_count = defaultdict(int)
        self.ip_count = defaultdict(int)
        self.port_count = defaultdict(int)

        # Attack tracking
        self.ip_to_ports = defaultdict(set)
        self.syn_count = defaultdict(int)
        self.failed_attempts = defaultdict(int)

        # Time-based tracking
        self.request_rate = defaultdict(list)
        self.dest_connection_count = defaultdict(int)
        self.dest_to_sources = defaultdict(set)

        self.alerts = []

    # ──────────────── HELPER ──────────────── #
    def get_val(self, packet, key):
        if isinstance(packet, dict):
            return packet.get(key)
        return getattr(packet, key, None)

    # ──────────────── ALERT ──────────────── #
    def generate_alert(self, attack_type, ip, count):
        # Suppress duplicates (one alert per type + ip)
        for alert in self.alerts:
            if alert["type"] == attack_type and alert["ip"] == ip:
                return

        # Per-attack-type severity bands
        severity_map = {
            "Port Scan":          (40,  80),
            "SYN Flood":          (200, 500),
            "Brute Force Attack": (20,  60),
            "DDoS Attack":        (500, 800),
            "Distributed Attack": (80,  150),
            "High Traffic Spike": (300, 600),
        }

        low_t, high_t = severity_map.get(attack_type, (100, 200))

        if count > high_t:
            severity = "HIGH"
        elif count > low_t:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        self.alerts.append({
            "type":     attack_type,
            "ip":       ip,
            "count":    count,
            "severity": severity,
            "time":     datetime.now().strftime("%H:%M:%S")
        })

    # ──────────────── MAIN PROCESS ──────────────── #
    def process_packet(self, packet):
        self.total_packets += 1

        protocol  = self.get_val(packet, "protocol")
        src_ip    = self.get_val(packet, "src_ip")
        dest_ip   = self.get_val(packet, "dst_ip") or self.get_val(packet, "dest_ip")
        src_port  = self.get_val(packet, "src_port")
        dest_port = self.get_val(packet, "dst_port") or self.get_val(packet, "dest_port")
        flags     = self.get_val(packet, "flags")

        # ── BASIC STATS (counted for ALL packets) ── #
        if protocol:
            self.protocol_count[protocol] += 1

        if self.mode == "src":
            if src_ip:  self.ip_count[src_ip] += 1
        elif self.mode == "dst":
            if dest_ip: self.ip_count[dest_ip] += 1
        else:
            if src_ip:  self.ip_count[src_ip] += 1
            if dest_ip: self.ip_count[dest_ip] += 1

        if src_port:  self.port_count[src_port] += 1
        if dest_port: self.port_count[dest_port] += 1

        # ── SKIP ATTACK CHECKS FOR WHITELISTED IPs ── #
        # Known CDN / cloud / LAN traffic is always normal — skip it
        if is_whitelisted(src_ip) or is_whitelisted(dest_ip):
            return

        # ── ATTACK DETECTION (unknown/external IPs only) ── #

        # 1. Port Scan
        # Unknown IP probing many non-standard ports on your machine
        if src_ip and dest_port and dest_port not in NORMAL_PORTS:
            self.ip_to_ports[src_ip].add(dest_port)
            if len(self.ip_to_ports[src_ip]) > 40:
                self.generate_alert("Port Scan", src_ip, len(self.ip_to_ports[src_ip]))

        # 2. SYN Flood
        # Flood of TCP connection requests from one unknown IP
        if protocol == "TCP" and flags == "S":
            if src_ip:
                self.syn_count[src_ip] += 1
                if self.syn_count[src_ip] > 200:
                    self.generate_alert("SYN Flood", src_ip, self.syn_count[src_ip])

        # 3. Brute Force
        # Repeated hits on sensitive ports (SSH, FTP, Telnet, RDP, VNC)
        # Port 443 removed — that is just regular HTTPS web traffic
        if dest_port in SENSITIVE_PORTS:
            if src_ip:
                self.failed_attempts[src_ip] += 1
                if self.failed_attempts[src_ip] > 20:
                    self.generate_alert("Brute Force Attack", src_ip, self.failed_attempts[src_ip])

        # 4. DDoS Detection
        # Massive packet flood to one destination within 5 seconds
        if dest_ip:
            now = datetime.now().timestamp()
            self.request_rate[dest_ip].append(now)
            self.request_rate[dest_ip] = [
                t for t in self.request_rate[dest_ip] if now - t < 5
            ]
            if len(self.request_rate[dest_ip]) > 500:
                self.generate_alert("DDoS Attack", dest_ip, len(self.request_rate[dest_ip]))

        # 5. Distributed Attack
        # Many different unknown IPs all targeting the same destination
        if dest_ip and src_ip:
            self.dest_to_sources[dest_ip].add(src_ip)
            if len(self.dest_to_sources[dest_ip]) > 80:
                self.generate_alert("Distributed Attack", dest_ip, len(self.dest_to_sources[dest_ip]))

        # 6. Traffic Spike
        # One unknown source sending too many packets in 10 seconds
        if src_ip:
            now = datetime.now().timestamp()
            self.request_rate[src_ip].append(now)
            self.request_rate[src_ip] = [
                t for t in self.request_rate[src_ip] if now - t < 10
            ]
            if len(self.request_rate[src_ip]) > 300:
                self.generate_alert("High Traffic Spike", src_ip, len(self.request_rate[src_ip]))

    # ──────────────── SUMMARY ──────────────── #
    def print_summary(self):
        print("\n------------- ANALYSIS SUMMARY ------------")
        print("Total packets captured :", self.total_packets)

        print("\nProtocol distribution")
        for p, count in self.protocol_count.items():
            print(f"  {p}: {count}")

        print("\nTop 5 IPs")
        for ip, count in sorted(self.ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            tag = " (whitelisted - normal)" if is_whitelisted(ip) else " (unknown - watch this)"
            print(f"  {ip}{tag}: {count} packets")

        print("\nTop 5 ports")
        for port, count in sorted(self.port_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  Port {port}: {count}")

        print("\nAlerts Detected")
        if not self.alerts:
            print("  No suspicious activity — all traffic looks normal.")
        for alert in self.alerts:
            print(f"  [{alert['severity']}] {alert['type']} → {alert['ip']} "
                  f"({alert['count']} attempts) at {alert['time']}")