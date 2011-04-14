#! /bin/bash

. /lib/lsb/init-functions

log_warning_msg "configuring networking..."

route add -net 130.121.0.0 netmask 255.255.0.0 dev eth0

log_warning_msg "Starting HIP service"


# create a tun dev, if necessary  (don't know why...)
if [ ! -e /dev/net/tun ]; then
	log_warning_msg "TUN/TAP device missing..attempting to create"
	mkdir -p /dev/net
	mknod /dev/net/tun c 10 200
fi

if [ -e /var/run/hip.pid ]; then
        log_warning_msg "deleting stale PID file"
        rm -rf /var/run/hip.pid
fi

#if [ -e /usr/local/etc/hip/hip.conf ]; then
#	log_warning_msg "backing up HIP configuration"
#	mv -f /usr/local/etc/hip/hip.conf /usr/local/etc/hip/hip.conf.old
#fi

#cd /etc/hip/tempcert
#./tcget_hl --pin 123456

cd /usr/local/etc/hip

if [ ! -e /usr/local/etc/hip/hip.conf ]; then
 log_failure_msg "Error - HIP configuration failed!"
 exit 0;
fi

log_warning_msg "Starting HIP daemon"
mv /var/log/hip/hip.log /var/log/hip/hip.log-`date +"%Y%m%d%H%M%S"`
/usr/local/etc/hip/bridge_down.sh
nohup /usr/local/sbin/hip -v > /var/log/hip/hip.log &
ifconfig hip0 mtu 1500
log_success_msg "Done"
