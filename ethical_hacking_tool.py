import requests
import os
import sys
import socket
import ipaddress
import time
from scapy.all import ARP, Ether, srp
from bs4 import BeautifulSoup

print("[+] Use Only for ethical purpuses")

def brute_force_directories():
    url=input("[+] Please Enter the URL of the Target Website: ")
    worlist = "common.txt" #Replace with the name of you wordlist file
    
    with open(worlist, 'r') as f:
        directories = f.read().splitlines()
        
    for directory in directories:
        target_url = f"{url}/{directory}"
        response = requests.get(target_url)
        
        if response.status_code == 200:
            print(f"[+] Found directory: {target_url}")
        elif response.status_code == 403:
            print(f"[+] Access forbidden: {target_url}")
        elif response.status_code == 404:
            print(f"[+] Not found: {target_url}")
        
def scan_network():
    if os.geteuid() != 0:
        print("[+] This script must be run as root. Please call command with sudo")
        sys.exit()
    
    network_range = input("[+] Enter the network range (e.g.: 192.168.1.0/24): ")
    port_range = [1, 21, 22, 80, 443]
    
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]
    
    for sent, received in result:
        print(f"[+] Device IP: {received.psrc}, MAC: {received.hwsrc}")
        
