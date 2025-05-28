import sys
from net import NetScanner
import argparse

def main():
    
    parser = argparse.ArgumentParser(description="Network scanner")
    parser.add_argument("-ip", "--ip_range", help="Target IP address", required=True)
    parser.add_argument("-sS", "--syn_scan", help="Enable SYN scan", action="store_true")
    args = parser.parse_args()

    Scanner = NetScanner(args.ip_range)
    if Scanner.validateIPRange():
        if args.syn_scan:
            Scanner.synScan()
        else:
            Scanner.arpScanner()


    
if __name__ == "__main__":
    main()