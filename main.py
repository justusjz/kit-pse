import os

from src.checker import Checker
from scapy.all import sniff
from src.logging.logger import Logger
from src.conf import SNIFF_FILTER, SNIFF_INTERFACE

checker = Checker()


def packet_handler(packet):
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
    sniff(prn=packet_handler, store=False, iface=SNIFF_INTERFACE, filter=SNIFF_FILTER)
    Logger.info("Packet capture completed.\n\n")


if __name__ == "__main__":
    main()
