import logging
import time
from collections import defaultdict

from scapy.all import sniff, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet import Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR

from tcp import tcp_connections, TcpConnection
from scapy.packet import Packet

import signature
import requests
import fragment

db = signature.SignatureDb("signatures.json")
frag_checker = fragment.FragmentChecker()

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

malicious_ips = set([])

arp_table = dict()


def arp_spoofing(packet):
    if packet[ARP].op == 2:
        mac = packet[ARP].hwsrc
        ip = packet[ARP].psrc
        if ip in arp_table:
            old_mac = arp_table[ip]
            if old_mac != mac:
                # different MAC than before
                log_malicious_packet(packet, "ARP spoofing detected")
        else:
            # previously unknown IP
            arp_table[ip] = mac


def ip_spoofing(packet, src_ip: str):
    if src_ip not in reserved_ips:
        if (
            src_ip.startswith("10.")
            or src_ip.startswith("192.168.")
            or src_ip.startswith("169.254.")
        ):
            log_malicious_packet(
                packet, "Possible IP spoofing using private networks detected."
            )

        elif src_ip.startswith("172."):
            octet = int(src_ip.split(".")[1])
            if 16 <= octet <= 31:
                log_malicious_packet(
                    packet, "Possible IP spoofing using private networks detected."
                )


def syn_fin(packet):
    tcp_flags = packet[TCP].flags
    if "S" in tcp_flags and "F" in tcp_flags:
        log_malicious_packet(packet, "SYN-FIN combination.")


def fin_rst(packet):
    # packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="FIN|RST")
    tcp_flags = packet[TCP].flags
    if "R" in tcp_flags and "F" in tcp_flags:
        log_malicious_packet(packet, "RST-FIN combination.")


def rst_syn(packet):
    # packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="SYN|RST")
    tcp_flags = packet[TCP].flags
    if "S" in tcp_flags and "R" in tcp_flags:
        log_malicious_packet(packet, "RST-SYN combination.")


def xmas(packet):
    # packet = IP(dst="192.168.1.1") / TCP(dport=80, flags="FIN|PSH|URG")
    tcp_flags = packet[TCP].flags
    if "P" in tcp_flags and "F" in tcp_flags and "U" in tcp_flags:
        log_malicious_packet(packet, "XMAS combination.")


def null_packet(packet):
    tcp_flags = packet[TCP].flags
    if tcp_flags == 0:
        log_malicious_packet(packet, "Malicious null packet found.")


def port_check(packet):
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    if src_port == 0 or dst_port == 0:
        log_malicious_packet(
            packet, "Illegal packet with source or destination port 0."
        )


def destination_check(packet):
    if IP in packet:
        dest_ip = packet[IP].dst
        if dest_ip.endswith(".0") or dest_ip.endswith(".255"):
            log_malicious_packet(
                packet, "Packets with broadcast destination address detected."
            )


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


def tcp_handshake_check(packet):
    # order the IPs and ports to make them unique per connection
    if IP in packet:
        src = min(packet[IP].src, packet[IP].dst)
        dst = min(packet[IP].src, packet[IP].dst)
    else:
        src = min(packet[IPv6].src, packet[IPv6].dst)
        dst = min(packet[IPv6].src, packet[IPv6].dst)
    sport = min(packet[TCP].sport, packet[TCP].dport)
    dport = max(packet[TCP].sport, packet[TCP].dport)
    key = (src, dst, sport, dport)
    if key in tcp_connections:
        connection = tcp_connections[key]
    else:
        connection = TcpConnection()
        tcp_connections[key] = connection
    # check that the TCP handshake is correct
    # when we detect an error, log it, and mark the connection
    # as acknowledged, so we don't spam errors
    if connection.state == "initial":
        if packet[TCP].flags == "S":
            connection.state = "syn"
        else:
            log_malicious_packet(packet, "Invalid TCP handshake flags (expected S)")
            connection.state = "ack"
    elif connection.state == "syn":
        if packet[TCP].flags == "SA":
            connection.state = "synack"
        else:
            log_malicious_packet(packet, "Invalid TCP handshake flags (expected SA)")
            connection.state = "ack"
    elif connection.state == "synack":
        if packet[TCP].flags == "A":
            connection.state = "ack"
        else:
            log_malicious_packet(packet, "Invalid TCP handshake flags (expected A)")
            connection.state = "ack"


def checksum_check(packet):
    if IP in packet:
        # packet = IP(dst="10.11.12.13", src="10.11.12.14")/UDP(chksum=0)/DNS()
        original_checksum = packet[IP].chksum  # saves original checksum for comparison
        del packet[IP].chksum  # deletes the current checksum
        recalculated_checksum = IP(
            bytes(packet[IP])
        ).chksum  # Scapy recalculates the checksum
        if original_checksum != recalculated_checksum:
            log_malicious_packet(packet, "Invalid IP checksum.")

    if TCP in packet:
        original_checksum = packet[TCP].chksum  # saves original checksum for comparison
        del packet[TCP].chksum  # deletes the current checksum
        recalculated_checksum = TCP(
            bytes(packet[TCP])
        ).chksum  # Scapy recalculates the checksum
        if original_checksum != recalculated_checksum:
            log_malicious_packet(packet, "Invalid TCP checksum.")


def malformed_packet(packet):
    maximum_header_length = 15
    minimum_header_length = 5
    if IP in packet:
        header_length = packet[IP].ihl
        total_length = packet[IP].len
        actual_length = len(packet[IP])
        maximum_length = 65535
        if header_length is None or total_length is None:
            pass
        elif (
            header_length > maximum_header_length
            or header_length < minimum_header_length
        ):
            log_malicious_packet(
                packet, "Malformed packet detected. IP header length is malformed."
            )
        elif total_length > maximum_length:
            log_malicious_packet(
                packet,
                "Malformed packet detected. Total length exceeds maximum length.",
            )
        elif total_length != actual_length:
            log_malicious_packet(
                packet,
                "Malformed packet detected. Total length does not equal actual length.",
            )
        protocol_number = packet[IP].proto
        if protocol_number == 255:
            log_malicious_packet(
                packet, "Malformed packet detected. Protocol number is reserved."
            )
    if TCP in packet:
        header_length = packet[TCP].dataofs
        if header_length is None:
            pass
        elif (
            header_length > maximum_header_length
            or header_length < minimum_header_length
        ):
            log_malicious_packet(
                packet, "Malformed packet detected. TCP header length is malformed."
            )


def fetch_blocklist_ips():
    """Fetches suspicious ips from blocklist.de from the last 12 hours,
    and returns them as a list"""
    url = "https://api.blocklist.de/getlast.php?time=00:00"
    try:
        print("[INFO] Load IP-List from Blocklist.de....")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        ip_list = response.text.strip().split("\n")
        return ip_list
    except requests.RequestException as e:
        print(f"[ERROR] Failed fetching the Blocklist.de IPs: {e}")
        return []


def dns_spoofing(packet):
    if DNS in packet:
        dns_layer = packet[DNS]
        if dns_layer.qr == 1:  # qr = 1 means response

            for i in range(dns_layer.ancount):  # package can have multiple responses
                dns_record = dns_layer.an[i]

                if dns_record.type == 1:  # A record
                    answered_ip = dns_record.rdata
                    if answered_ip in malicious_ips:
                        log_malicious_packet(
                            packet,
                            f"Suspicious DNS response detected!\n"
                            f"Domain: {dns_record.rrname.decode(errors='ignore')}\n"
                            f"Malicious IP: {answered_ip}",
                        )


def fragment_overlap_check(packet: Packet):
    src = packet[IP].src
    dst = packet[IP].dst
    frag_id = packet[IP].id
    # fragment size is measured in multiples of 8 octets
    frag_size = len(packet[IP].payload) / 8
    frag_offset = packet[IP].frag
    more_frags = "MF" in packet.flags
    if more_frags or frag_offset > 0:
        # this packet is fragmented, because either:
        # more fragments after this one
        # frag_offset > 0, so there were already fragments
        result = frag_checker.check(
            src, dst, frag_id, frag_size, frag_offset, more_frags
        )
        if result != None:
            log_malicious_packet(packet, result)


def packet_handler(packet):
    if ARP in packet:
        arp_spoofing(packet)

    if IP in packet:
        src_ip = packet[IP].src
        ip_spoofing(packet, src_ip)
        destination_check(packet)
        icmp_flood(packet)
        fragment_overlap_check(packet[IP])

    if TCP in packet:
        tcp_handshake_check(packet)
        syn_fin(packet)
        fin_rst(packet)
        rst_syn(packet)
        xmas(packet)
        null_packet(packet)
        port_check(packet)

    match = db.detect(packet.__bytes__())
    if match != None:
        log_malicious_packet(packet, match)
    checksum_check(packet)
    dns_spoofing(packet)
    malformed_packet(packet)
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
    malicious_ips.update(set(fetch_blocklist_ips()))  # fetch malicious ips
    print("Starting packet capture... Logs will be saved to:", LOG_FILE)
    logging.info("Starting packet capture...")
    sniff(prn=packet_handler, store=False)
    logging.info("Packet capture completed.\n\n")


if __name__ == "__main__":
    main()
