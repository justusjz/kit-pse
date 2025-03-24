from src.check.check import Check
from src.check.ml.ml_check import MLCheck
from src.logging.logger import Logger
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from time import time


class TcpConnection:
    state: str
    begin: float
    last_packet: float
    initiator: str
    port: int
    finisher: str | None
    src_bytes: int
    dst_bytes: int
    # number of urgent packets
    urgent: int

    def __init__(self, initiator: str, port: int):
        self.state = "initial"
        self.begin = time()
        self.last_packet = time()
        self.initiator = initiator
        self.port = port
        self.finisher = None
        self.src_bytes = 0
        self.dst_bytes = 0
        self.urgent = 0


tcp_connections = dict[(str, str, int, int), TcpConnection]()


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

# fields are documented here: https://kdd.ics.uci.edu/databases/kddcup99/task.html
# flags are documented here: https://www.cs.unc.edu/~jeffay/dirt/FAQ/comp290-042/tcp-reduce.html


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
        # find the connection, or create a new one
        if key in tcp_connections:
            connection = tcp_connections[key]
        else:
            connection = TcpConnection(src, dport)
            tcp_connections[key] = connection
        # we got a new packet for this connection
        connection.last_packet = time()
        # check timed-out connections
        _process_timeouts()
        # count number of urgent packets
        if "U" in packet[TCP].flags:
            connection.urgent += 1
        # update src and dst bytes
        if src == connection.initiator:
            connection.src_bytes += len(bytes(packet))
        else:
            connection.dst_bytes += len(bytes(packet))
        # analyze the flags
        if connection.state == "initial":
            # the connection hasn't started yet
            if src == connection.initiator and packet[TCP].flags == "S":
                # typical connection start
                connection.state = "syn"
            else:
                Logger.log_malicious_packet(
                    packet, "Invalid TCP handshake flags (expected S)"
                )
                connection.state = "ack"
        elif connection.state == "syn":
            # we are now in state 0, initial SYN seen, but no reply
            if dst == connection.initiator and packet[TCP].flags == "SA":
                connection.state = "synack"
            elif dst == connection.initiator and packet[TCP].flags == "R":
                # connection was rejected, not necessarily suspicious
                _terminate_connection(key, "REJ")
            elif src == connection.initiator and packet[TCP].flags == "R":
                # connection was rejected by initiator (originator) in state 0
                _terminate_connection(key, "RSTOS0")
            else:
                if "F" in packet[TCP].flags:
                    # connection was closed before being initiated
                    _terminate_connection(key, "SH")
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
        elif connection.state == "finack":
            if dst == connection.initiator and packet[TCP].flags == "A":
                _terminate_connection(key, "SF")


def _process_timeouts():
    for key, connection in list(tcp_connections.items()):
        if time() - connection.last_packet <= 30:
            continue
        # connections are timed out if there are no packets
        # sent for at least 30 seconds
        if connection.state == "syn":
            # initial SYN, but no reply
            _terminate_connection(key, "S0")
        elif connection.state == "synack":
            # connection established, but nothing since then
            _terminate_connection(key, "S1")
        else:
            # other connection flag
            _terminate_connection(key, "OTH")


def _terminate_connection(key: tuple[str, str, int, int], flag: str):
    connection = tcp_connections.pop(key)
    # duration in seconds
    duration = time() - connection.begin
    if connection.port in service_map:
        service = service_map[connection.port]
    elif connection.port >= 49152:
        # private/ephemeral port
        service = "private"
    else:
        # unknown port
        service = "other"
    MLCheck.check(
        "tcp",
        flag,
        service,
        duration,
        connection.src_bytes,
        connection.dst_bytes,
        key[0] == key[1]
        or key[2] == key[3],  # land if the connection is from/to the same host/port
        connection.urgent,
    )
