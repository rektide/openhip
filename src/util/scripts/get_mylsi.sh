#!/bin/sh

cmd="/sbin/ip addr show dev hip0"
LSIIP=`$cmd | grep "\<inet\>" | awk '/inet/ {print $2}'`
# 1.2.3.4/8
echo $LSIIP | awk -F '/' '{ print $1;}'
