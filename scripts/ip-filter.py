#!/usr/bin/python

from IPy import IP
import sys

for line in sys.stdin:
    try:
        ip = IP(line.strip())
        if ip.iptype() == 'PUBLIC':
            print(ip.strCompressed())
    finally:
        continue
