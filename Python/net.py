import scapy.all as scapy

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
