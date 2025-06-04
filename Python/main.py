from net import NetScanner
import argparse
from utils.help import isRoot
import sys
from utils.const import ERROR_PRIVILIGES
from utils.ui import print_error

def main():

    parser = argparse.ArgumentParser(prog="Network scanner", description="Tool for scanning subnets, ports")
    
    parser.add_argument("-ip", "--ip_range", help="Target IP address", required=True)
    parser.add_argument("-sS", "--syn_scan", help="Enable SYN scan", action="store_true")
    parser.add_argument("-pS", "--ping_scan", help="ICMP ping scan", action="store_true")# store_true = indicate that is a boolean expresion
    parser.add_argument("-rM", "--resolve_mac", help="Resolve mac addresses from companies", action="store_true")
    parser.add_argument("-p", "--port", help="Scan the ports you enter")
    args = parser.parse_args()

    Scanner = NetScanner(args.ip_range, args.resolve_mac, args.port)
    if Scanner.validateIPRange():
        if args.port:
            Scanner.defaultPortScan()
        else:
            if args.syn_scan:
                if isRoot():
                    Scanner.synScan()
                else:
                    print_error(ERROR_PRIVILIGES)
            elif args.ping_scan:
                if isRoot():
                    Scanner.pingScan()
                else:
                    print_error(ERROR_PRIVILIGES)
            else:
                if isRoot():
                    Scanner.arpScan()
                else:
                    print_error(ERROR_PRIVILIGES)

    
if __name__ == "__main__":
    main()