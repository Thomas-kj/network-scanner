#!/usr/bin/env python3

import scapy.all as spy

def scan(ip):
    
    # use arp to ask who has the target ip:
    arp_request = spy.ARP(pdst=ip)
    
    # set the destination to broadcast Mac Address:
    broadcast = spy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    # combine both the above into one single packet:
    arp_request_broadcast = broadcast / arp_request
    
    print("[+] Started Scanning Network")
    answered_list = spy.srp(arp_request_broadcast, timeout=2)[0]

    print("IP\t\t\t\t\tMAC ADDRESS\n------------------------------------")

    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)

# scans address from 10.0.2.1 to 10.0..2.254:
scan("10.0.2.1/24")

print("\n---------**SCAN COMPLETE**---------")
