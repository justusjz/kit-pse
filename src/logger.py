import logging
import os

from scapy.layers.inet import IP, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6


class Logger:
    __log_file = "run.log"  # File where logs will be saved
    __log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        filename=__log_file,
        level=__log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    @classmethod
    def log(cls, message: str):
        logging.info(message)

    @classmethod
    def log_error(cls, message):
        logging.error(message)

    @classmethod
    def log_malicious_packet(cls, packet, warning: str):
        log_details = [
            f"Malicious Packet Detected: {warning}",
            f"MAC Address of malicious agent: {packet[Ether].src if Ether in packet else 'N/A'}",
            f"Source IP: {packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else 'N/A'}, "
            f"Destination IP: {packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else 'N/A'}",
            f"Source Port: {packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 'N/A'}, "
            f"Destination Port: {packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 'N/A'}",
        ]
        logging.warning("\n".join(log_details))

    @classmethod
    def get_log_file_name(cls) -> str:
        return cls.__log_file
