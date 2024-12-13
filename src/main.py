import scapy.all as scapy
import signature

db = signature.SignatureDb("signatures.json")

def packet_handler(packet: scapy.Packet):
    match = db.detect(packet.__bytes__())
    if match != None:
        print(f"Detected malicious signature: {match}")

def main():
    scapy.sniff(prn=packet_handler)

if __name__ == "__main__":
    main()
