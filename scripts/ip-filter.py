#!/bin/python

from IPy import IP
import sys

for line in sys.stdin:
    ip = IP(line.strip())
    if ip.iptype() == 'PUBLIC':
        print(ip.strCompressed())
