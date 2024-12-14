from scapy.config import conf

conf.debug_dissector = 2
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

reserved_ips = ["192.168.1.4", "192.168.1.1", "192.168.1.7", "172.16.0.3"]


def ip_spoofing(src_mac, src_ip):
    # Ensure src_ip is not None before processing
    if src_ip not in reserved_ips:
        if (
            src_ip.startswith("10.")
            or src_ip.startswith("192.168.")
            or src_ip.startswith("169.254.")
        ):
            print("Possible IP spoofing using private networks detected.")
    elif src_ip.startswith("172."):
        octet = int(src_ip.split(".")[1])  # Only set octet for 172.x.x.x IPs
        if 16 <= octet <= 31:
            print("Possible IP spoofing using private networks detected.")


def syn_fin(packet):
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if "S" in tcp_flags and "F" in tcp_flags:
            print("Malicious packet detected: SYN-FIN combination.")
            print(f"MAC Address of malicious agent: {packet[Ether].src}")


def fin_rst(packet):
    # packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="FIN|RST")
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if "R" in tcp_flags and "F" in tcp_flags:
            print("Malicious packet detected: RST-FIN combination.")
            print(f"MAC Address of malicious agent: {packet[Ether].src}")


def rst_syn(packet):
    # packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="SYN|RST")
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if "S" in tcp_flags and "R" in tcp_flags:
            print("Malicious packet detected: RST-SYN combination.")
            print(f"MAC Address of malicious agent: {packet[Ether].src}")


def xmas(packet):
    # packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="FIN|PSH|URG")
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if "P" in tcp_flags and "F" in tcp_flags and "U" in tcp_flags:
            print("Malicious packet detected: XMAS combination.")
            print(f"MAC Address of malicious agent: {packet[Ether].src}")


def null_packet(packet):
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if tcp_flags == 0:
            print("Malicious null packet found.")
            print(f"MAC Address of malicious agent: {packet[Ether].src}")


def port_check(packet):
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        if src_port == 0 or dst_port == 0:
            print("Illegal packet with source or destination port 0.")
            print(f"MAC Address of malicious agent: {packet[Ether].src}")


def destination_check(packet):
    if IP in packet:
        dest_ip = packet[IP].dst
        if dest_ip.endswith(".0") or dest_ip.endswith(".255"):
            print("Packets with broadcast destination address detected.")
            print(f"MAC Address of malicious agent: {packet[Ether].src}")


def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    src_mac = packet[Ether].src if Ether in packet else None

    print(f"Packet captured: {src_ip} -> {dst_ip}")
    ip_spoofing(src_mac, src_ip)

    if TCP in packet:
        rst_syn(packet)
        fin_rst(packet)
        xmas(packet)
        syn_fin(packet)
        null_packet(packet)
        port_check(packet)

    destination_check(packet)


def main():
    print("Starting packet capture...")
    sniff(prn=packet_handler, store=False, count=5)


if __name__ == "__main__":
    main()
