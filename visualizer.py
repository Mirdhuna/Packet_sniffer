import matplotlib.pyplot as plt

class Visualizer:
    def __init__(self,analyzer):
        self.analyzer=analyzer

    def plot_protocol_distribution(self):
        protocols=list(self.analyzer.protocol_count.keys())
        counts=list(self.analyzer.protocol_count.values())

        plt.figure()
        plt.pie(counts,labels=protocols,autopct='%1.1f%%')
        plt.title("Protocol distribution")
        plt.show()

    def plot_top_ips(self):
        sorted_ips = sorted(self.analyzer.ip_count.items(), key=lambda x: x[1], reverse=True)

        ips = [ip for ip, _ in sorted_ips]
        counts = [count for _, count in sorted_ips]
        
        plt.figure(figsize=(18, 6))   # wider figure for all IPs
        plt.bar(ips, counts)
        plt.title("All IP Addresses")
        plt.xlabel("IP Address")
        plt.ylabel("Packet Count")
        plt.xticks(rotation=45, ha='right')   # better angle for readability
        plt.tight_layout()   # prevents label cutoff
        plt.show()

    def plot_top_ports(self):
        sorted_ports = sorted(self.analyzer.port_count.items(),key=lambda x: x[1],reverse=True)
        ports = [str(port) for port, _ in sorted_ports]
        counts = [count for _, count in sorted_ports]

        plt.figure()
        plt.bar(ports, counts)
        plt.title("Top Ports")
        plt.xlabel("Port")
        plt.ylabel("Usage Count")
        plt.show()
