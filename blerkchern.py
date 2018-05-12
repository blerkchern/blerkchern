#!/usr/bin/env python2

from hashlib import sha256
import sys
from itertools import count

def main():
    data = sys.argv[1]

    for i in count():
        text = data + str(i)
        result = long(sha256(text).hexdigest(), 16)
        if property_check(result):
            print 'Succeeded:', text
            break


def property_check(hash):
    return hash % 10001 == 0

if __name__ == '__main__':
    main()
