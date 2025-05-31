import sys
from net import NetScanner
import argparse

def main():
    
    parser = argparse.ArgumentParser(prog="Network scanner", description="Tool for scanning subnets, ports")
    parser.add_argument("-ip", "--ip_range", help="Target IP address", required=True)
    parser.add_argument("-sS", "--syn_scan", help="Enable SYN scan", action="store_true")
    parser.add_argument("-pS", "--ping_scan", help="ICMP ping scan", action="store_true")# store_true = indicate that is a boolean expresion
    parser.add_argument("-rM", "--resolve_mac", help="Resolve mac addresses from companies", action="store_true")
    args = parser.parse_args()

    Scanner = NetScanner(args.ip_range, args.resolve_mac)
    if Scanner.validateIPRange():
        if args.syn_scan:
            Scanner.synScan()
        elif args.ping_scan:
            Scanner.pingScan()
        else:
            Scanner.arpScan()


    
if __name__ == "__main__":
    main()