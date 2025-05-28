import scapy.all as scapy
import re
import socket

class NetScanner:
    def __init__(self, ip_range):
        self.ip_range = ip_range
        self.clients

    def arpScanner(self):
        arp = scapy.ARP(pdst=self.ip_range)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        res = scapy.srp(packet, timeout=1)[0]
        clients = []
        for sent, recived in res:
            clients.append({'ip': recived.psrc, 'mac': recived.hwsrc})
        
        print("Available devices in the network: ")
        print("IP" + " "*18+"MAC")
        print("-----------------------------------")
        for client in clients:
            print("{:16}      {}".format(client['ip'], client['mac']))
    
    def synScan():
        return True

    def validateIPRange(self):
        regex = "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9]|0)$"
        match = re.search(regex, self.ip_range)
        if(match):
            return True
        else:
            return False
    
    def printResults(self):
        return self.clients
    
    @staticmethod
    def getLocalAddress():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Create UDP socket AF_NET = IPv4, SOCK_DGRAM = UDP - SOCK_STREAM = TCP
        try:
            s.connect(("8.8.8.8", 80))# Setup routing table, to know which interface to grab
            ip_parts = s.getsockname()[0].split('.')
        finally:
            s.close()
        ip_parts[3] = '0'
        cidr = '.'.join(ip_parts) + '/24'
        
        return cidr
