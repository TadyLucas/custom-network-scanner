import sys
import help
import net

def main():
    ip_address = ""
    for arg in sys.argv:
        if(help.validateIPRange(arg)):
            ip_address = arg
            break
        else:
            continue
    if not ip_address:
        ip_address = help.getLocalAddress()
        print(ip_address)

    if(not help.is_root):
        sys.exit("Try again with SUDO or root priviliges e.g. (sudo python3 main.py 10.10.10.0/24)")
    else:
        net.arpScanner(ip_address)

    


    
if __name__ == "__main__":
    main()