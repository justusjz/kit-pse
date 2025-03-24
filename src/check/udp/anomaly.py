from src.check.check import Check
from src.check.ml.ml_check import MLCheck
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from time import time


service_map = {
    53: "domain_u",
    69: "tftp_u",
    123: "ntp_u",
}


class UdpConnection:
    begin: float
    initiator: str
    service: str
    src_bytes: int

    def __init__(self, initiator: str, port: int, src_bytes: int):
        self.begin = time()
        self.initiator = initiator
        if port in service_map:
            self.service = service_map[port]
        elif port >= 49152:
            # private/ephemeral port
            self.service = "private"
        else:
            # unknown port
            self.service = "other"
        self.src_bytes = src_bytes


udp_connections = dict[(str, str, int, int), UdpConnection]()


class UdpAnomaly(Check):
    def __init__(self):
        super().__init__()

    @classmethod
    def check(cls, packet):
        # check timed-out connections
        _process_timeouts()
        if IP in packet:
            src, dst = packet[IP].src, packet[IP].dst
        else:
            src, dst = packet[IPv6].src, packet[IPv6].dst
        sport, dport = packet[UDP].sport, packet[UDP].dport
        # unique key for this UDP "connection"
        key = (min(src, dst), max(src, dst), min(sport, dport), max(sport, dport))
        # find the connection, or create a new one
        if key in udp_connections:
            # since this is UDP, a "connection" consists
            # of just the two packets
            _terminate_connection(key, len(bytes(packet)))
        else:
            connection = UdpConnection(src, dport, len(bytes(packet)))
            udp_connections[key] = connection


def _process_timeouts():
    for key, connection in list(udp_connections.items()):
        if time() - connection.begin <= 30:
            continue
        # this UDP packet didn't get a response, so just set
        # dst_bytes to 0
        _terminate_connection(key, 0)


def _terminate_connection(key: tuple[str, str, int, int], dst_bytes: int):
    connection = udp_connections.pop(key)
    duration = time() - connection.begin
    MLCheck.check(
        "udp",
        "SF",
        connection.service,
        duration,
        connection.src_bytes,
        dst_bytes,
        key[0] == key[1]
        or key[2] == key[3],  # land if connection is from/to the same host/port
        0,
    )
