#!/bin/bash
olif="eth1"

ifconfig hipbr down
brctl delif hipbr $olif
brctl delif hipbr hip0
brctl delbr hipbr

exit 0
