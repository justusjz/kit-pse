from src.check.check import Check
from src.logging.logger import Logger
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from src.test.tcp import tcp_connections, TcpConnection


class Handshake(Check):
    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
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
                Logger.log_malicious_packet(
                    packet, "Invalid TCP handshake flags (expected S)"
                )
                connection.state = "ack"
        elif connection.state == "syn":
            if packet[TCP].flags == "SA":
                connection.state = "synack"
            else:
                Logger.log_malicious_packet(
                    packet, "Invalid TCP handshake flags (expected SA)"
                )
                connection.state = "ack"
        elif connection.state == "synack":
            if packet[TCP].flags == "A":
                connection.state = "ack"
            else:
                Logger.log_malicious_packet(
                    packet, "Invalid TCP handshake flags (expected A)"
                )
                connection.state = "ack"
