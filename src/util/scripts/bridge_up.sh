#!/bin/bash
mylsi=`awk '/LSI/ {print $1}' /usr/local/etc/hip/my_host_identities.xml|awk -F '>' '{print $2}'|awk -F '<' '{print $1}'`
hn=`hostname`
if [ "$mylsi"X = "X" ]; then
  echo Error: cannot find this host LSI from my_host_identities.xml
fi
if [ "$hn"X = "ebicsX" ]; then
  olif="eth1"
  ifconfig $olif 0.0.0.0
else
  olif="eth2"
fi
brctl addbr hipbr
brctl addif hipbr $olif
brctl addif hipbr hip0
ifconfig hip0 mtu 1500
if [ "$hn"X = "ebicsX" ]; then
  ifconfig hipbr up 192.168.0.100
  ip addr add $mylsi dev hipbr
else
  ifconfig hipbr up $mylsi
fi
ip route add 1.0.0.0/8 dev hipbr
