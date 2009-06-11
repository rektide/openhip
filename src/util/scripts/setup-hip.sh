#!/bin/sh

# set the device here
#DEV=wlan0
#DEV=vmnet1
DEV=eth0

# read src address from device
SRC=`ip -4 addr show dev $DEV | grep inet | awk '{split($2, a, "/"); print a[1];}'`

# dst address is given
DST=$1

echo setting up policy $SRC ==\> $DST

/usr/local/sbin/setkey -c << EOF
flush;
spdflush;

spdadd $SRC $DST any -P out ipsec
	hip/transport//require;
EOF

echo done.
