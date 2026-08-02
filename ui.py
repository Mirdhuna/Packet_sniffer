import streamlit as st
import matplotlib.pyplot as plt
import json
import time
from analyzer import Packet_analyzer

st.set_page_config(page_title="Packet Sniffer", layout="wide")

st.title("📡 Real-Time Packet Sniffer Dashboard")

# ---------------- SETTINGS ---------------- #

REFRESH_INTERVAL = 3

# Mode selector
mode_option = st.selectbox(
    "🔍 Select IP Counting Mode",
    ["Source Only", "Destination Only", "Both"]
)

# Map UI to analyzer mode
if mode_option == "Source Only":
    analyzer = Packet_analyzer(mode="src")
elif mode_option == "Destination Only":
    analyzer = Packet_analyzer(mode="dst")
else:
    analyzer = Packet_analyzer(mode="both")

st.info("Source = Sender IP | Destination = Receiver IP")

# ---------------- LOAD DATA ---------------- #

def load_packets():
    try:
        with open("packets.json", "r") as f:
            return json.load(f)
    except:
        return []

packets = load_packets()

# Process packets
for packet in packets:
    analyzer.process_packet(packet)

# ---------------- SUMMARY ---------------- #

st.subheader("📊 Summary")
col1, col2 = st.columns(2)
col1.metric("Total Packets", analyzer.total_packets)
col2.metric("Unique IPs", len(analyzer.ip_count))

# ---------------- PROTOCOL ---------------- #

st.subheader("Protocol Distribution")

protocols = list(analyzer.protocol_count.keys())
proto_counts = list(analyzer.protocol_count.values())   # ← renamed to proto_counts

if proto_counts:
    fig1, ax1 = plt.subplots()
    ax1.pie(proto_counts, labels=protocols, autopct='%1.1f%%')
    st.pyplot(fig1)
else:
    st.warning("No protocol data available")

# ---------------- ALL IPs CHART ---------------- #

st.subheader(f"All IP Addresses ({mode_option})")

# Get ALL IPs sorted by packet count
all_ips = sorted(analyzer.ip_count.items(), key=lambda x: x[1], reverse=True)

if all_ips:
    total_unique = len(all_ips)

    # ── FIXED SLIDER ──
    # Use total_unique (number of IPs) for the slider range,
    # NOT the protocol counts which caused the min==max crash.
    slider_min = 1
    slider_max = total_unique if total_unique > 1 else 2   # guard: max must be > min
    slider_default = min(total_unique, 10)

    top_n = st.slider(
        "Select how many IPs to display in chart",
        min_value=slider_min,
        max_value=slider_max,
        value=slider_default,
        step=1
    )

    display_ips = all_ips[:top_n]
    ips    = [ip for ip, _ in display_ips]
    counts = [c  for _,  c in display_ips]

    # Dynamic figure width based on number of IPs
    fig_width = max(12, top_n * 0.6)
    fig2, ax2 = plt.subplots(figsize=(fig_width, 5))
    bars = ax2.bar(ips, counts, color='steelblue')

    # Add count labels on top of each bar
    for bar, count in zip(bars, counts):
        ax2.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.3,
            str(count),
            ha='center', va='bottom', fontsize=8
        )

    ax2.set_title(f"Top {top_n} IP Addresses (out of {total_unique} unique IPs)")
    ax2.set_xlabel("IP Address")
    ax2.set_ylabel("Packet Count")
    plt.xticks(rotation=45, ha='right', fontsize=8)
    plt.tight_layout()
    st.pyplot(fig2)

    # ---------------- FULL IP TABLE ---------------- #

    st.subheader(f"📋 All {total_unique} IP Addresses — Full Table")

    # Search/filter box
    search = st.text_input("🔎 Search IP address", "")

    # Build table data
    table_data = []
    for rank, (ip, count) in enumerate(all_ips, start=1):
        if search and search not in ip:
            continue
        table_data.append({
            "Rank":         rank,
            "IP Address":   ip,
            "Packet Count": count,
            "% of Total":   f"{(count / analyzer.total_packets * 100):.1f}%"
        })

    if table_data:
        st.table(table_data)
    else:
        st.warning(f"No IP matching '{search}' found.")

else:
    st.warning("No IP data available")

# ---------------- TOP PORTS ---------------- #

st.subheader("Top Ports")

top_ports = sorted(analyzer.port_count.items(), key=lambda x: x[1], reverse=True)[:10]

if top_ports:
    ports   = [str(p) for p, _ in top_ports]
    pcounts = [c for _, c in top_ports]

    fig3, ax3 = plt.subplots(figsize=(10, 4))
    ax3.bar(ports, pcounts, color='darkorange')
    ax3.set_title("Top 10 Ports")
    ax3.set_xlabel("Port")
    ax3.set_ylabel("Usage Count")
    plt.tight_layout()
    st.pyplot(fig3)
else:
    st.warning("No port data available")

# ---------------- ALERTS ---------------- #

st.subheader("🚨 Security Alerts")

def get_color(severity):
    if severity == "HIGH":
        return "red"
    elif severity == "MEDIUM":
        return "orange"
    else:
        return "green"

if analyzer.alerts:
    for alert in analyzer.alerts:
        color = get_color(alert["severity"])

        explanations = {
            "Port Scan":          f"🔍 IP {alert['ip']} scanned {alert['count']} different ports — trying to find open doors into your system.",
            "SYN Flood":          f"💥 IP {alert['ip']} sent {alert['count']} SYN requests — trying to crash your server by overloading connections.",
            "Brute Force Attack": f"🔑 IP {alert['ip']} tried {alert['count']} times on SSH/FTP/RDP — trying to guess your password.",
            "DDoS Attack":        f"🌊 IP {alert['ip']} flooded {alert['count']} packets in 5 seconds — trying to take your server offline.",
            "Distributed Attack": f"🕸️ {alert['count']} different IPs all attacked {alert['ip']} together — coordinated attack.",
            "High Traffic Spike": f"📈 IP {alert['ip']} sent {alert['count']} packets in 10 seconds — abnormal traffic burst.",
        }

        explanation = explanations.get(alert['type'], f"IP {alert['ip']} triggered {alert['count']} suspicious events.")

        st.markdown(f"""
        <div style='border-left: 4px solid {color}; padding: 10px; margin: 8px 0; background-color: #1e1e1e; border-radius: 4px;'>
            <b style='color:{color}'>[{alert['severity']}] {alert['type']}</b><br>
            🌐 <b>Attacker IP:</b> {alert['ip']}<br>
            🕒 <b>Time:</b> {alert['time']}<br>
            📊 <b>Count:</b> {alert['count']}<br>
            💬 <b>What it means:</b> {explanation}
        </div>
        """, unsafe_allow_html=True)
else:
    st.success("✅ No attacks detected — all traffic looks normal!")

# ---------------- AUTO REFRESH ---------------- #

time.sleep(REFRESH_INTERVAL)
st.rerun()