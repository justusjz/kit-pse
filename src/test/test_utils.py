from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
import src.main as main


def send_test_tcp_packet(packet: Packet):
    packet[IP].chksum = IP(bytes(packet[IP])).chksum
    packet[TCP].chksum = TCP(bytes(packet[TCP])).chksum
    main.packet_handler(packet)


def send_test_packet(packet: IP):
    packet.chksum = IP(bytes(packet)).chksum
    main.packet_handler(packet)
