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
