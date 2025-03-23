import logging
import sys

from scapy.layers.inet import IP, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6
from src.logging.slack import SlackClient
from src.conf import LOG_LEVEL


class Logger:
    __log_file = "run.log"  # File where logs will be saved
    __log_level = LOG_LEVEL.upper()  # Convert log level to uppercase

    # Create a logger
    logger = logging.getLogger(__name__)
    logger.setLevel(__log_level)

    # Create a formatter
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Create a file handler
    file_handler = logging.FileHandler(__log_file)
    file_handler.setLevel(__log_level)
    file_handler.setFormatter(formatter)

    # Create a console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(__log_level)
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    __slack_logger = SlackClient()

    @classmethod
    def info(cls, message: str):
        logging.info(message)

    @classmethod
    def debug(cls, message: str):
        logging.debug(message)

    @classmethod
    def error(cls, message):
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
        log_message = "\n".join(log_details)
        logging.warning(log_message)
        cls.__slack_logger.send_message(log_message)

    # TODO: Method should be more flexible
    @classmethod
    def log_prediction(cls, packet_df, prediction: str):
        message = (
            f"Prediction: {prediction}\n"
            f"Details of connection:\n"
            f"  Protocol: {packet_df['protocol_type'][0]}\n"
            f"  Flag: {packet_df['flag'][0]}\n"
            f"  Service: {packet_df['service'][0]}\n"
            f"  Duration: {packet_df['duration'][0]} sec\n"
            f"  Src Bytes: {packet_df['src_bytes'][0]}\n"
            f"  Dst Bytes: {packet_df['dst_bytes'][0]}"
        )
        logging.warning(message)
        cls.__slack_logger.send_message(message)

    @classmethod
    def get_log_file_name(cls) -> str:
        return cls.__log_file
