import os

from src.checker import Checker
from scapy.all import sniff, TCPSession
from src.logging.logger import Logger

checker = Checker()


def packet_handler(packet):
    print(packet)
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
    sniff(session=TCPSession, prn=packet_handler, store=False)
    Logger.info("Packet capture completed.\n\n")


if __name__ == "__main__":
    main()
