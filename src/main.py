import logging
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.inet import Ether
from scapy.layers.inet6 import IPv6

# Configure the logger
LOG_FILE = "packet_logs.log"  # File where logs will be saved
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Reserved IPs list
reserved_ips = ["192.168.1.4", "192.168.1.1", "192.168.1.7", "172.16.0.3"]


def ip_spoofing(packet, src_mac: str, src_ip: str):
    if src_ip not in reserved_ips:
        if (
            src_ip.startswith("10.")
            or src_ip.startswith("192.168.")
            or src_ip.startswith("169.254.")
        ):
            log_ip_spoofing(packet, src_mac, src_ip)

        elif src_ip.startswith("172."):
            octet = int(src_ip.split(".")[1])
            if 16 <= octet <= 31:
                log_ip_spoofing(packet, src_mac, src_ip)


def syn_fin(packet):
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if "S" in tcp_flags and "F" in tcp_flags:
            logging.warning("Malicious packet detected: SYN-FIN combination.")
            log_malicious_packet(packet, "TCP")


def null_packet(packet):
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if tcp_flags == 0:
            logging.warning("Malicious null packet found.")
            log_malicious_packet(packet, "TCP")


def port_check(packet):
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        if src_port == 443 or dst_port == 443:
            logging.warning("Illegal packet with source or destination port 0.")
            log_malicious_packet(packet, "TCP")


def destination_check(packet):
    if IP in packet:
        dest_ip = packet[IP].dst
        if dest_ip.endswith(".0") or dest_ip.endswith(".255"):
            logging.warning("Packets with broadcast destination address detected.")
            log_malicious_packet(packet, "TCP")


def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_mac = packet[Ether].src if Ether in packet else None
        logging.info(f"Packet captured: {src_ip} -> {dst_ip}")
        ip_spoofing(packet, src_mac, src_ip)

    if TCP in packet:
        syn_fin(packet)
        null_packet(packet)
        port_check(packet)
        destination_check(packet)


def log_ip_spoofing(packet, src_mac: str, src_ip: str):
    logging.warning(
        "Possible IP spoofing using private networks detected. MAC %s, IP: %s",
        src_mac,
        src_ip,
    )
    log_malicious_packet(packet, "IP")


def log_malicious_packet(packet, packet_type: str):
    if IP in packet:
        logging.warning(
            f"MAC Address of malicious agent: {packet[Ether].src}\n"
            + f"Captured {packet_type} Packet: {packet.summary()}\n"
            + f"Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}\n"
        )

    if IPv6 in packet:
        logging.warning(
            f"MAC Address of malicious agent: {packet[Ether].src}\n"
            + f"Captured {packet_type} Packet: {packet.summary()}\n"
            + f"Source IP: {packet[IPv6].src}, Destination IP: {packet[IPv6].dst}\n"
        )

    if TCP in packet:
        logging.warning(
            f"Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}"
        )


def main():
    print("Starting packet capture... Logs will be saved to:", LOG_FILE)
    logging.info("Starting packet capture...")
    sniff(prn=packet_handler, store=False)
    logging.info("Packet capture completed.\n\n")


if __name__ == "__main__":
    main()
