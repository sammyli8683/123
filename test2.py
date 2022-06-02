#!/usr/bin/env python
from scapy.all import *
from scapy.contrib.gtp import *
sendp([Ether()/IP(src="172.16.27.3",dst="172.16.27.1")/UDP(dport=2152)/GTP_U_Header(gtp_type=255, teid=0x000001)/GTPPDUSessionContainer(type=0, P=1, QFI=0x01)/IP(src="172.16.31.1",dst="172.16.28.0")/UDP()],iface="ens1")
