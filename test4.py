#!/usr/bin/env python
from scapy.all import *
from scapy.contrib.gtp import *
sendp([Ether()/IP(src="172.16.31.1", dst="172.16.28.0")/UDP(dport=2152)],iface="ens1")

