#!/bin/sh
ldapsearch -x -D "cn=crawler,dc=sma,dc=boeing,dc=com" -w secret -s sub -b "" "objectclass=*"
