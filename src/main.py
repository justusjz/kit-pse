import logging
import time
from collections import defaultdict

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import Ether
from scapy.layers.inet6 import IPv6

import signature

db = signature.SignatureDb("signatures.json")

# Configure the logger
LOG_FILE = "packet_logs.log"  # File where logs will be saved
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

ICM_THRESHOLD = 100
ICM_TIMEINTERVAL = 60

# Reserved IPs list
reserved_ips = ["192.168.1.4", "192.168.1.1", "192.168.1.7", "172.16.0.3"]
icmp_count = defaultdict(int)
last_reset = time.time()  # reset timer for icmp flood


def ip_spoofing(packet, src_ip: str):
    if src_ip not in reserved_ips:
        if (
                src_ip.startswith("10.")
                or src_ip.startswith("192.168.")
                or src_ip.startswith("169.254.")
        ):
            log_malicious_packet(packet, "Possible IP spoofing using private networks detected.")

        elif src_ip.startswith("172."):
            octet = int(src_ip.split(".")[1])
            if 16 <= octet <= 31:
                log_malicious_packet(packet, "Possible IP spoofing using private networks detected.")


def syn_fin(packet):
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if "S" in tcp_flags and "F" in tcp_flags:
            log_malicious_packet(packet, "Malicious packet detected: SYN-FIN combination.")


def null_packet(packet):
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if tcp_flags == 0:
            log_malicious_packet(packet, "Malicious null packet found.")


def port_check(packet):
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        if src_port == 0 or dst_port == 0:
            log_malicious_packet(packet, "Illegal packet with source or destination port 0.")


def destination_check(packet):
    if IP in packet:
        dest_ip = packet[IP].dst
        if dest_ip.endswith(".0") or dest_ip.endswith(".255"):
            log_malicious_packet(packet, "Packets with broadcast destination address detected.")


# Detects potential ICMP flood attacks by tracking ICMP packets per source IP in time interval.
def icmp_flood(packet, reset_interval=ICM_TIMEINTERVAL, threshold=ICM_THRESHOLD):
    global last_reset
    current_time = time.time()

    # Reset the ICMP count periodically
    if current_time - last_reset > reset_interval:
        icmp_count.clear()
        last_reset = current_time

    if ICMP in packet:
        src_ip = packet[IP].src
        icmp_count[src_ip] += 1

        if icmp_count[src_ip] > threshold:
            log_malicious_packet(packet, "Potential ICMP flood detected.")

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        ip_spoofing(packet, src_ip)
        destination_check(packet)
        icmp_flood(packet)

    if TCP in packet:
        syn_fin(packet)
        null_packet(packet)
        port_check(packet)

    match = db.detect(packet.__bytes__())
    if match != None:
        log_malicious_packet(packet, match)

    logging.debug(f"Captured Packet: {packet.summary()}\n")


def log_malicious_packet(packet, warning: str):
    log_details = [
        f"Malicious Packet Detected: {warning}",
        f"MAC Address of malicious agent: {packet[Ether].src if Ether in packet else 'N/A'}",
        f"Source IP: {packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else 'N/A'}, "
        f"Destination IP: {packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else 'N/A'}",
        f"Source Port: {packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 'N/A'}, "
        f"Destination Port: {packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 'N/A'}",
    ]
    logging.warning("\n".join(log_details))


def main():
    print("Starting packet capture... Logs will be saved to:", LOG_FILE)
    logging.info("Starting packet capture...")
    sniff(prn=packet_handler, store=False)
    logging.info("Packet capture completed.\n\n")


if __name__ == "__main__":
    main()
