import re
from os import getuid

def validateIPRange(ip):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9]|0)$"
    match = re.search(regex, ip)
    if(match):
        return True
    else:
        return False

def is_root():
    return getuid() == 0