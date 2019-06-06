#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    # IP Packet
    ip_packet = scapy.ARP(pdst=ip)

    # Ethernet Frame
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combining above two to make an ARP request for set IP/range and broadcast MAC
    arp_request = ether_frame/ip_packet

    # Send and Receive the protocol created above. By default returns two lists [answered, unanswered]. We capture only answered ones
    answered = scapy.srp(arp_request, timeout=1)[0] # Using srp instead of scapy.sr because we have custom made Ethernet frame
    return answered

def result_display(answered):
    # Parse the response
    print("\n\t Captured ARP packets")
    print("-------------------------------------------------------")
    print("\tIP\t\tMAC Address")
    print("-------------------------------------------------------")
    lst = []
    for element in answered:
        dict = {'IP': element[1].psrc, 'MAC' : element[1].hwsrc}
        lst.append(dict)
    for item in lst:
        print("     " + item['IP'] + "\t     " + item['MAC'])