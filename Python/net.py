import scapy.all as scapy
import re
import socket
import ipaddress
import logging
import tqdm
from manuf import manuf
from tabulate import tabulate

class NetScanner:
    def __init__(self, ip_range, resolveMac):
        self.ip_range = ip_range
        self.clients = []
        self.timeout = 1
        self.resolveMac = resolveMac

    def arpScan(self):
        vendor = ""

        scapy.conf.verb = 0
        arp = scapy.ARP(pdst=self.ip_range)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        head="ARP scan"

        res = scapy.srp(packet, timeout=1)[0]
        for sent, recived in res:
            if self.resolveMac:
                parser = manuf.MacParser()
                vendor = parser.get_manuf(recived.hwsrc)
                self.clients.append({'ip':recived.psrc, 'mac':recived.hwsrc, 'vendor': vendor})
            else:
                self.clients.append({'ip':recived.psrc, 'mac':recived.hwsrc})
        
        if self.resolveMac:
            self.printProcess(head=head, columns=['ip', 'mac', 'vendor'])
        else:
            self.printProcess(head=head, columns=['ip', 'mac'])

    def pingScan(self):
        logging.getLogger("scapy. runtime").setLevel(logging.ERROR)
        head = "Ping scan"
        scapy.conf.verb = 0
        if "/" in self.ip_range:
            try:
                ips = list(ipaddress.IPv4Network(self.ip_range, strict=False))
                for ip in tqdm.tqdm(ips, desc="Pinging"):
                    pkt = scapy.IP(dst=str(ip))/scapy.ICMP()
                    reply = scapy.sr1(pkt, timeout=self.timeout, verbose=0)
                    if reply:
                        self.addToClients(ip=str(ip))
                self.printProcess(head=head)
            except ValueError as e:
                self.printProcess(error=f"Invalid subnet {e}", head=head)
        else:
            pkt = scapy.IP(dst=self.ip_range)/scapy.ICMP()
            reply = scapy.sr1(pkt, timeout=self.timeout)
            if reply:
                self.addToClients(ip=self.ip_range)
                self.printProcess(head=head)
            else:
                self.printProcess(error="Host is not alive", head=head)

    # def synScan(self):
    #     return True
    def printProcess(self, head="", error="", columns=['ip', 'mac']):
        print(f"\nResults of {head}:\n")

        if error:
            print(f"Error: {error}")
            return
        
         # Dynamic header names (title-case)
        headers = [col.replace("_", " ").title() for col in columns]

        # Build the table rows
        table_data = []
        for client in self.clients:
            row = [client.get(col, "N/A") for col in columns]
            table_data.append(row)

        print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

        
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
