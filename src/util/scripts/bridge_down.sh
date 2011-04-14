#!/bin/bash
hn=`hostname`
if [ "$hn"X = "ebicsX" ]; then
  olif="eth1"
else
  olif="eth2"
fi
ifconfig hipbr down
brctl delif hipbr $olif
brctl delif hipbr hip0
brctl delbr hipbr
if [ "$hn"X = "ebicsX" ]; then
  ifconfig $olif 192.168.0.100
fi
