# First of all i installed both scapy and pyshark using the command lin 'pip install scapy
# '''in the venv/bin/activate'''

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

    # Check if the packet contains TCP layer
    packet_info == {"protocol": "TCP","source_ip": source_ip,"source_port": source_port,"destination_ip": destination_ip,"destination_port": destination_port}
        
    # Write JSON data to the file
    log.write(json.dumps(packet_info) + "\n")
    print (log.txt)
        
        
# Main function to start packet sniffing
def main(interface, verbose=False):
    
    # Create log file name based on interface
    logfile_name = f"sniffer_{interface}_log.json"
    
    # Open log file for writing
    with open(logfile_name, 'w') as logfile:
        try:
            # Start packet sniffing on specified interface with verbose output
            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, verbose=verbose)
        except KeyboardInterrupt:
            print("\nSniffing stopped by user")
            sys.exit(0)
            
# Check if the script is being run directly
if __name__ == "__main__":
    
    # Check if the correct number of arguments is provided
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py [verbose]")
        sys.exit(1)
        
    #Determine if verbose mode is enabled
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
        
    # Call the main function with the specified interface and verbose option
    main(sys.argv[1], verbose)
    
