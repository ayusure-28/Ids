from scapy.all import sniff, IP, TCP, UDP, conf
from db import log_alert, is_ip_blocked, block_ip # Import new functions
import threading
import time

try:
    sniff(count=1, timeout=1) 
    print("Scapy L2 sniffing (Npcap) is available.")
except Exception:
    print("Scapy L2 sniffing (Npcap) not available. Falling back to L3 sockets.")
    conf.L3socket = True

packet_count = 0
alert_count = 0
auto_block_enabled = False # New flag for auto-block

COMMON_PORTS = {80, 443, 22, 53, 25, 110, 143, 3306, 5432}

def analyze_packet(packet):
    """Analyzes a single packet."""
    global packet_count, alert_count, auto_block_enabled
    packet_count += 1

    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # --- PREVENTION STEP ---
            # If the source IP is on our blocklist, ignore the packet
            if is_ip_blocked(src_ip):
                # In a real system, you'd also have a firewall rule.
                # For now, we just stop processing and logging it.
                return 
            # ---------------------

            proto = ""
            details = ""
            is_anomaly = False

            if packet.haslayer(TCP):
                proto = "TCP"
                dport = packet[TCP].dport
                if dport not in COMMON_PORTS:
                    details = f"Unusual destination port: {dport}"
                    is_anomaly = True
            
            elif packet.haslayer(UDP):
                proto = "UDP"
                dport = packet[UDP].dport
                if dport not in COMMON_PORTS:
                    details = f"Unusual destination port: {dport}"
                    is_anomaly = True

            if is_anomaly:
                print(f"[ALERT] Anomaly Detected: {src_ip} -> {dst_ip} on port {dport}")
                log_alert("Unusual Port", src_ip, dst_ip, proto, details)
                alert_count += 1
                
                # --- AUTO-BLOCK STEP ---
                if auto_block_enabled:
                    print(f"[AUTO-BLOCK] Blocking IP: {src_ip}")
                    block_ip(src_ip, "Auto-block: Unusual Port Activity")
                # ---------------------

    except Exception as e:
        print(f"Error analyzing packet: {e}")


# --- Sniffer Control ---
sniffer_active = False
sniffer_thread = None

def start_sniffer():
    global sniffer_active, sniffer_thread, packet_count, alert_count
    if sniffer_thread is None or not sniffer_thread.is_alive():
        packet_count = 0
        alert_count = 0
        sniffer_active = True
        sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        sniffer_thread.start()
        print("Sniffer started...")
        return True
    return False

def stop_sniffer():
    global sniffer_active
    sniffer_active = False
    print("Sniffer stopping...")
    if sniffer_thread is not None and sniffer_thread.is_alive():
        sniffer_thread.join() 
    print("Sniffer fully stopped.")
    return True

def run_sniffer():
    global sniffer_active
    print("Sniffer thread running...")
    
    while sniffer_active:
        try:
            sniff(prn=analyze_packet, 
                  stop_filter=lambda p: not sniffer_active,
                  timeout=1)
        except Exception as e:
             print(f"Sniffing error: {e}, restarting sniff...")
             time.sleep(1)
    print("Sniffer thread stopped.")