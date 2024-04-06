#!/bin/sh

tcpdump -i any -p -nn | grep "IP" | awk '{print $5}' | sed 's/\.[^.]*$//' | ./ip-filter.py
