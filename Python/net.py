import scapy.all as scapy
import re
import socket
import time

class NetScanner:
    def __init__(self, ip_range):
        self.ip_range = ip_range
        self.clients = []

    def arpScan(self):
        scapy.conf.verb = 0
        arp = scapy.ARP(pdst=self.ip_range)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        res = scapy.srp(packet, timeout=1)[0]
        clients = []
        for sent, recived in res:
            self.clients.append(ip=recived.psrc, mac=recived.hwsrc)
        self.printProcess(head="ARP scan")
        
    def pingScan(self):
        head = "Ping scan"
        clients = []
        scapy.conf.verb = 0
        if "/" in self.ip_range:
            idk = 0
        else:
            pkt = scapy.IP(dst=self.ip_range)/scapy.ICMP()
            reply = scapy.sr1(pkt, timeout=1)
            if reply:
                self.addToClients(ip=self.ip_range)
                self.printProcess(head=head)
            else:
                self.printProcess(error="Host is not alive", head=head)

    # def synScan(self):
    #     return True
    
    def printProcess(self, head="", error=""):
        print(f"Results of {head}: \n")
       
        if error:
            print(f"Error: {error}")
        else:
            print("IP" + " "*18+"MAC")
            print("-----------------------------------")
            for client in self.clients:
                print("{:16}      {}".format(client['ip'], client['mac']))
    
    def validateIPRange(self):
        regex = r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}" \
                r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])" \
                r"(\/(3[0-2]|[12]?[0-9]|0))?$"        
        match = re.search(regex, self.ip_range)
        if(match):
            return True
        else:
            return False
    def addToClients(self, ip="0.0.0.0", mac="None"):
        self.clients.append({'ip':ip, 'mac':mac})
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
