#!/bin/sh

# get SRC addr from dev (doesn't always work)
DEV=eth0
#DEV=wlan0
#DEV=tun
#SRC=2002:56ff:1c1c:8:290:4bff:fe19:6f82
SRC=`ip -6 addr show dev $DEV | grep inet6 | awk '{split($2, a, "/"); print a[1];}'`

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
