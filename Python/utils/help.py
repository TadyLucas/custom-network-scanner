from os import getuid


def isRoot():
    return getuid() == 0

