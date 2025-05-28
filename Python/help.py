from os import getuid

    

def is_root():
    return getuid() == 0

