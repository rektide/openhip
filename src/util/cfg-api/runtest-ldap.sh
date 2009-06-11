#!/bin/sh
LD_LIBRARY_PATH=/root/sc/lib:/home/jfang/hip/src/cfg-ldap:$LD_LIBRARY_PATH
export LD_LIBRARY_PATH
 ./test_hipcfg
