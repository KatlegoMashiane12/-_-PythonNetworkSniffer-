#Import necessary modules from Scapy library
import scapy.all as scapy
from scapy.layers import http

#Function to sniff packets on a specified network interface
def sniff_packets(interface):
    
    scapy.sniff(iface=interface, store=False, prn=process_packet)

# Callback function to process each captured packet
def process_packet(packet):
    if http.HTTPRequest in packet:
        print("Host: " + packet[http.HTTPRequest].Host)

# Call the sniff_packets function with the desired network interface (e.g., 'Wi-Fi')
sniff_packets('Wi-Fi')
