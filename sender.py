#!/usr/bin/python
from scapy.all import *

def raw_http(src, dst, request="GET /\r\n", sport=10000, dport=80):
    ip=IP(src=src, dst=dst)
    SYN=TCP(sport=sport, dport=dport, flags="S", seq=100)
    SYNACK=sr1(ip/SYN)
    my_ack = SYNACK.seq + 1

    print my_ack

    ACK=TCP(sport=sport, dport=dport, flags="A", seq=101, ack=my_ack)
    ACK2 = sr1(ip/ACK)
    my_ack = ACK2.seq + 1

    print my_ack

    payload = Raw(request)
    PUSH=TCP(sport=sport, dport=dport, flags="PA", seq=102, ack=my_ack)
    ANS = sr1(ip/PUSH/payload)

    return ANS


print raw_http("192.168.1.56", "192.168.1.1")
