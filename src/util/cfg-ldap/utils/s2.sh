#!/bin/sh
ldapsearch -x -D "cn=crawler,dc=sma,dc=boeing,dc=com" -w secret -s onelevel -b "dc=endboxes,dc=sma,dc=boeing,dc=com" "objectclass=endbox" 
