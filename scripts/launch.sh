#!/bin/sh

tcpdump -i eth0 -p -nn | grep "IP" | awk '{print $5}' | sed 's/\.[^.]*$//' | ./ip-filter.py
