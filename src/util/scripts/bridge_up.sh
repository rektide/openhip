#!/bin/bash

mylsi=`/usr/local/etc/hip/get_mylsi.sh`
hn=`hostname`

if [ "$mylsi"X = "X" ]; then
  logger -s "Error: cannot find this host LSI from my_host_identities.xml"
  exit -1
fi

#Underlay Interface - connection to infrastructure network
ulif="eth0"
#Overlay Interface - connection to private network
olif="eth1"

brctl addbr hipbr
brctl addif hipbr $olif
brctl addif hipbr hip0
ifconfig hip0 mtu 1500
ifconfig hipbr up $mylsi
ip route add 1.0.0.0/8 dev hipbr

logger -s "Bridge up with - LSI: $mylsi   hostname: $hn  underlay_if: $ulif  overlay_if: $olif"

exit 0

