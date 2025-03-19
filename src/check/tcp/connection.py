from src.check.check import Check
from src.check.ml.check import ml_check_connection
from src.logging.logger import Logger
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from time import time


class TcpConnection:
    state: str
    begin: float
    initiator: str
    port: int
    finisher: str | None
    src_bytes: int
    dst_bytes: int

    def __init__(self, initiator: str, port: int):
        self.state = "initial"
        self.begin = time()
        self.initiator = initiator
        self.port = port
        self.finisher = None
        self.src_bytes = 0
        self.dst_bytes = 0


tcp_connections = dict[TcpConnection]()


# in some tests, we're not performing a TCP handshake, but that
# shouldn't matter, so we can ignore it with this method
def tcp_handshake_ignore(src: str, dst: str, sport: int, dport: int):
    conn = TcpConnection(src, dport)
    conn.state = "ack"
    tcp_connections[(src, dst, sport, dport)] = conn


# TODO: we might want to extend this
service_map = {
    23: "telnet",
    25: "smtp",
    80: "http",
    110: "pop_3",
    443: "https",
}


class Connection(Check):
    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        if IP in packet:
            src, dst = packet[IP].src, packet[IP].dst
        else:
            src, dst = packet[IPv6].src, packet[IPv6].dst
        sport, dport = packet[TCP].sport, packet[TCP].dport
        # unique key for this TCP connection
        key = (min(src, dst), max(src, dst), min(sport, dport), max(sport, dport))
        if key in tcp_connections:
            connection = tcp_connections[key]
        else:
            connection = TcpConnection(src, dport)
            tcp_connections[key] = connection
        if src == connection.initiator:
            connection.src_bytes += len(bytes(packet))
        else:
            connection.dst_bytes += len(bytes(packet))
        if connection.state == "initial":
            if src == connection.initiator and packet[TCP].flags == "S":
                connection.state = "syn"
            else:
                Logger.log_malicious_packet(
                    packet, "Invalid TCP handshake flags (expected S)"
                )
                connection.state = "ack"
        elif connection.state == "syn":
            if dst == connection.initiator and packet[TCP].flags == "SA":
                connection.state = "synack"
            else:
                Logger.log_malicious_packet(
                    packet, "Invalid TCP handshake flags (expected SA)"
                )
                connection.state = "ack"
        elif connection.state == "synack":
            if src == connection.initiator and packet[TCP].flags == "A":
                connection.state = "ack"
            else:
                Logger.log_malicious_packet(
                    packet, "Invalid TCP handshake flags (expected A)"
                )
                connection.state = "ack"
        elif connection.state == "ack":
            if packet[TCP].flags == "FA":
                connection.finisher = src
                connection.state = "fin"
        elif connection.state == "fin":
            if dst == connection.finisher and packet[TCP].flags == "FA":
                connection.state = "finack"
        if (
            connection.state == "finack"
            and src == connection.finisher
            and packet[TCP].flags == "A"
            or "R" in packet[TCP].flags
        ):
            # connection was terminated correctly or reset
            # TODO: duration in seconds?
            duration = int(time() - connection.begin)
            # TODO: figure out what the other flags mean
            if "R" in packet[TCP].flags:
                flag = "REJ"
            else:
                flag = "SF"
            if connection.port in service_map:
                service = service_map[connection.port]
            else:
                service = "private"
            ml_check_connection(
                "tcp",
                flag,
                service,
                duration,
                connection.src_bytes,
                connection.dst_bytes,
            )
            del tcp_connections[key]
