import os

from src.checker import Checker
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from src.logging.logger import Logger
from time import time

checker = Checker()

class TcpConnection:
    state: str
    begin: float
    initiator: str
    port: int
    finisher: str | None
    src_bytes: int
    dst_bytes: int

    def __init__(self, initiator: str, port: int):
        self.state = 'initial'
        self.begin = time()
        self.initiator = initiator
        self.port = port
        self.finisher = None
        self.src_bytes = 0
        self.dst_bytes = 0

tcp_connections = dict[TcpConnection]()


def packet_handler(packet):
    if TCP in packet:
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
        if connection.state == 'initial':
            if src == connection.initiator and packet[TCP].flags == 'S':
                connection.state = 'syn'
            else:
                # ignore
                connection.state = 'ack'
        elif connection.state == 'syn':
            if dst == connection.initiator and packet[TCP].flags == 'SA':
                connection.state = 'synack'
            else:
                connection.state = 'ack'
        elif connection.state == 'synack':
            if src == connection.initiator and packet[TCP].flags == 'A':
                print(f'3-way handshake complete for {src} <-> {dst}')
                connection.state = 'ack'
            else:
                connection.state = 'ack'
        elif connection.state == 'ack':
            if packet[TCP].flags == 'FA':
                connection.finisher = src
                connection.state = 'fin'
        elif connection.state == 'fin':
            if dst == connection.finisher and packet[TCP].flags == 'FA':
                connection.state = 'finack'
        elif connection.state == 'finack':
            if src == connection.finisher and packet[TCP].flags == 'A':
                # connection was terminated correctly
                duration = time() - connection.begin
                print(f'Connection terminated for {src} <-> {dst}')
                del tcp_connections[key]
        if packet[TCP].flags == 'R':
            print(f'Connection reset for {src} <-> {dst}')
            del tcp_connections[key]
        # print(packet[TCP])
    checker.check(packet)
    Logger.debug(f"Captured Packet: {packet.summary()}\n")


def main():
    if os.getenv("CLEAR_LOG") == "True":
        with open(Logger.get_log_file_name(), "w") as log_file:
            log_file.truncate(0)
    print(
        "Starting packet capture... Logs will be saved to:", Logger.get_log_file_name()
    )
    Logger.info("Starting packet capture...")
    sniff(prn=packet_handler, store=False)
    Logger.info("Packet capture completed.\n\n")


if __name__ == "__main__":
    main()
