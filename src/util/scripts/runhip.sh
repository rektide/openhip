#! /bin/bash

USE_SYSLOG=y

if [ -e /var/run/hip.pid ]; then
	logger -s "killing any running hip processes"
	killall hip || true
        logger -s "deleting stale PID file"
        rm -rf /var/run/hip.pid
	sleep 1
fi

if [ ! -e /usr/local/etc/hip/hip.conf ]; then
	logger -s "error - no hip.conf file found"
	exit 1;
fi

# create a tun dev, if necessary  (don't know why...)
if [ ! -e /dev/net/tun ]; then
	logger -s "TUN/TAP device missing..attempting to create"
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
fi

if [ -e /root/private_hosts ]; then
        logger -s "copying /root/private_hosts ARP table for legacy devices into /tmp"
        cp /root/private_hosts /tmp/
elif [ -e /tmp/private_hosts ]; then
	logger -s "removing /tmp/private_hosts ARP table for legacy devices"
	rm -f /tmp/private_hosts
fi

logger -s "Starting HIP daemon"

/usr/local/etc/hip/bridge_down.sh

if [ $USE_SYSLOG = "y" ]; then
    /usr/local/sbin/hip -v 2>&1 | (tee /dev/null | logger -t hiplog) &
else
    mv /var/log/hip/hip.log /var/log/hip/hip.log-`date +"%Y%m%d%H%M%S"`
    /usr/local/sbin/hip -v > /var/log/hip.log 2>&1 &
fi

ifconfig hip0 mtu 1500
