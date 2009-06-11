#!/bin/sh
ldapsearch -x -D "cn=crawler,dc=sma,dc=boeing,dc=com" -w secret -s onelevel -b "dc=endboxes,dc=sma,dc=boeing,dc=com" "(&(objectclass=endbox)(IpLegacyNodes=192.168.0.101))" EndboxLSI IpEndboxBCWIN  
