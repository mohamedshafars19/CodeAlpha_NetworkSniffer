from scapy.all import sniff, IP
import datetime

print("Starting Network Sniffer... Press Ctrl+C to stop\n")

def get_protocol_name(proto):
    if proto == 6:
        return "TCP"
    elif proto == 17:
        return "UDP"
    elif proto == 1:
        return "ICMP"
    else:
        return "Other"

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        timestamp = datetime.datetime.now()

        data = (
            f"Time: {timestamp} | "
            f"Source IP: {ip_layer.src} | "
            f"Destination IP: {ip_layer.dst} | "
            f"Protocol: {get_protocol_name(ip_layer.proto)}"
        )

        print(data)

        # Save to file
        with open("log.txt", "a") as file:
            file.write(data + "\n")

try:
    sniff(filter="tcp", prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\nSniffing stopped.")