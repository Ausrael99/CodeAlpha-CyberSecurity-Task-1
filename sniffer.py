from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw # type: ignore
from datetime import datetime

# Function to analyze each packet
def analyze_packet(packet): 
    print("\n--- New Packet ---") 
    print(f"Time: {datetime.now()}") 

    if IP in packet: 
        ip_layer = packet[IP] 
        print(f"Source IP: {ip_layer.src}") 
        print(f"Destination IP: {ip_layer.dst}") 
        print(f"Protocol: {ip_layer.proto}") 

        if TCP in packet: 
            print("Protocol: TCP") 
            print(f"Source Port: {packet[TCP]. sport}") 
            print(f"Destination Port: {packet[TCP].dport}") 

        elif UDP in packet: 
              print("Protocol: UDP") 
              print(f"Source Port: {packet[UDP].sport}") 
              print(f"Destination Port: {packet[UDP].dport}") 

        elif ICMP in packet: 
              print("Protocol: ICMP") 

        if Raw in packet: 
            print("Payload:") 
            print(packet[Raw]. load[:100]) # Print only the first 100 bytes 

    else: 
       print("No IP layer detected.")
# Start capture
print("Starting packet sniffing...Press Ctrl+C to stop.\n")
sniff(prn=analyze_packet, store=False)

