#!/bin/bash

tcpdump -i ens1 -w dump.pcap &
sleep 2
pid=$(ps -e | grep tcpdump) 
echo $pid
sleep 1
kill -2 $pid


tshark -r "ulgtp.pcap" > typein.txt
tshark -r "uludp.pcap" > typeout.txt
tshark -r "dlgtp.pcap" > typeout1.txt
tshark -r "dludp.pcap" > typein1.txt
tshark -r "ulgtp.pcap" -T fields -e ip.src -e ip.dst -E separator=, >ipin.txt
tshark -r "uludp.pcap" -T fields -e ip.src -e ip.dst -E separator=, >ipout.txt
tshark -r "dlgtp.pcap" -T fields -e ip.src -e ip.dst -E separator=, >ipout1.txt
tshark -r "dludp.pcap" -T fields -e ip.src -e ip.dst -E separator=, >ipin1.txt

cat qos_test.py|grep QFI > dlqfi.txt
tshark -r "dlgtp.pcap" -T json |grep gtp.ext_hdr.pdu_ses_con.qos_flow_id >dlqfi_n3.txt

sleep 1
g++ test1.cpp -o test.out
echo "###  test ul"
echo ul | ./test.out 
#sleep 1
echo -e "\n"
echo "###  test dl"
echo dl | ./test.out 


rm typein.txt
rm typein1.txt
rm typeout.txt
rm typeout1.txt
rm ipin.txt
rm ipout.txt
rm ipin1.txt
rm ipout1.txt
rm dlqfi.txt
rm dlqfi_n3.txt
