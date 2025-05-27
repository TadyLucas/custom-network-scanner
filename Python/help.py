import re
from os import getuid
import socket

def validateIPRange(ip):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9]|0)$"
    match = re.search(regex, ip)
    if(match):
        return True
    else:
        return False

def is_root():
    return getuid() == 0

def getLocalAddress():
    new_ip= ""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Create UDP socket AF_NET = IPv4, SOCK_DGRAM = UDP - SOCK_STREAM = TCP
    try:
        s.connect(("8.8.8.8", 80))# Setup routing table, to know which interface to grab
        ip_parts = s.getsockname()[0].split('.')
    finally:
        s.close()
    ip_parts[3] = '0'
    cidr = '.'.join(ip_parts) + '/24'
    
    return cidr