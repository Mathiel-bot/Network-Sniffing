import json
import sys
from scapy.all import sniff, IP, TCP

# Function to handle each packet
def handle_packet(packet, log):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        # Proper assignment here
        packet_info = {
            "protocol": "TCP",
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port
        }

        # Write JSON data to the file
        log.write(json.dumps(packet_info) + "\n")
        
        # Optional: print to console
        print(packet_info)

# Main function to start packet sniffing
def main(interface, verbose=False):
    logfile_name = f"sniffer_{interface}_log.json"
    with open(logfile_name, 'w') as logfile:
        try:
            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, verbose=verbose)
        except KeyboardInterrupt:
            print("\nSniffing stopped by user")
            sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)

    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True

    main(sys.argv[1], verbose)
