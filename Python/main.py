import socket
import sys
IP_ADDRESS = "0.0.0.0"
def main():
    for i in sys.argv:
        if isIP(i):
            IP_ADDRESS = i
            print("valid")
def isIP(ip):
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for i in parts:
            octet = int(i)
            if (octet > 255 or octet < 0):
                return False
        return True
    except:
        return False
    
if __name__ == "__main__":
    main()