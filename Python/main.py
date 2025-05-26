import scapy.all as scapy
import sys
import help

def main():
    if(help.is_root):
        sys.exit("Try again with SUDO or root priviliges e.g. (sudo python3 main.py 10.10.10.0/24)")
    
    ip_address =  "0.0.0.0/24"
    for arg in sys.argv:
        if(help.validateIPRange(arg)):
            ip_address = arg
            break
        else:
            continue
    arpScanner(ip_address)

    

def arpScanner(target):
    arp = scapy.ARP(pdst=target)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    res = scapy.srp(packet, timeout=1)[0]
    clients = []
    for sent, recived in res:
        clients.append({'ip': recived.psrc, 'mac': recived.hwsrc})
    
    print("Available devices in the network: ")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}      {}".format(client['ip'], client['mac']))

    
if __name__ == "__main__":
    main()