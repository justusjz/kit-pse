import os
import logging

from scapy.all import sniff

from src.logger import Logger
from src.checker import Checker

checker = Checker()


def packet_handler(packet):
    checker.check(packet)
    logging.debug(f"Captured Packet: {packet.summary()}\n")


def main():
    if os.getenv("CLEAR_LOG") == "True":
        with open(Logger.get_log_file_name(), "w") as log_file:
            log_file.truncate(0)
    print(
        "Starting packet capture... Logs will be saved to:", Logger.get_log_file_name()
     )
    logging.info("Starting packet capture...")
    sniff(prn=packet_handler, store=False)
    logging.info("Packet capture completed.\n\n")


if __name__ == "__main__":
    main()
