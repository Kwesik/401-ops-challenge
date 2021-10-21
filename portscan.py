#! /usr/bin/env python3

import random 
from ipaddress import IPv4Network
from scapy.all import ICMP, IP, sr1, TCP
from typing import List

# Define end host and TCP port range
network = "192.168.4.0/24"
port_range = [22, 23, 80, 443, 3389]

addresses = IPv4Network(network)
live_count = 0

# Send SYN with random Src Port for each Dst port
def port_scan(host: str, ports: List [int]):
    for dst_port in port_range:
        src_port = random.randint(1025,65534)
        response = sr1(
        IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=.01,
        verbose=0,
    )

    if response is None:
        print(f"{host}:{dst_port} is filtered (silently dropped).")

    elif(response.haslayer(TCP)):
        if(response.getlayer(TCP).flags == 0x12):
            # Send a gratuitous RST to close the connection
            response = sr1(
                IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                timeout=1,
                verbose=0,
            )
            print(f"{host}:{dst_port} is open.")

        elif (response.getlayer(TCP).flags == 0x14):
            print(f"{host}:{dst_port} is closed.")

    elif(response.haslayer(ICMP)):
        if(
            int(response.getlayer(ICMP).type) == 3 and
            int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]
        ):
            print(f"{host}:{dst_port} is filtered (silently dropped).")


    for host in addresses:
        if (host in (addresses.network_address, addresses.broadcast_address)):
            continue
        response = sr1(
            IP(dst=str(host))/ICMP(),
            timeout=.01,
            verbose=0
    )
        if response is None:
            print (f"{host} is down")
            
        elif response.haslayer(ICMP):
            if (int(response.getlayer(ICMP).type) == 3 and
                int(response.getlayer(ICMP).code) [1,2,3,9,10,13]):
                print (f"{host} is blocking ICMP traffic")
            
        else:
           port_scan(str(host), port_range)
print(f"{live_count}/{addresses.num_addresses} host are online.")