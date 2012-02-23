#!/usr/bin/python
import os
from random import randint
from scapy.all import *
from subprocess import Popen, PIPE


def command(x):
    return str(Popen(x.split(' '), stdout=PIPE).communicate()[0])


def raw_http(src, dst, request="GET /\r\n", sport=10000, dport=80):
    command("iptables -A OUTPUT -s %s -d %s -p tcp --sport %d --dport %d -j DROP" % (src, dst, sport, dport))

    try:
        data = {}

        ip = IP(src=src, dst=dst)
        seq = randint(10, 100) * 1000

        SYN=TCP(sport=sport, dport=dport, flags="S", seq=seq)
        SYNACK = sr1(ip/SYN)
        my_ack = SYNACK.seq + 1
        seq += 1

        send(ip/TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=my_ack))

        payload = Raw(request)
        PUSH=TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=my_ack)
        seq += 1 + len(payload)
        pkt = sr1(ip/PUSH/payload)

        # We need to recieve once more here

        while pkt:
            pkt.show()

            tcp = pkt.payload
            while (not isinstance(tcp, NoPayload)) and (tcp.name != 'TCP'):
                tcp = tcp.payload
            if isinstance(tcp, NoPayload): continue
            if tcp.dport != sport or tcp.sport != dport: continue

            data[tcp.seq] = tcp.payload
            my_ack = tcp.seq + len(tcp.payload)
            flags = "A"
            if tcp.flags % 2 == 1:
                flags = "FA"
            pkt_to_send = ip/TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=my_ack)
            print "Going to send",
            pkt_to_send.show()
            pkt = sr1(pkt_to_send)
            if tcp.flags % 2 == 1:
                break

        return data

    finally:
        command("iptables -D OUTPUT -s %s -d %s -p tcp --sport %d --dport %d -j DROP" % (src, dst, sport, dport))


def reset(src, dst, sport=10000, dport=80):
    send(IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="R"))

# raw_http("192.168.1.51", "192.168.1.1")


