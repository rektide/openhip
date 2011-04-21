#!/bin/sh

my_host_file=./my_host_identities.xml
LSIXML=`grep LSI $my_host_file | awk '/LSI/ {print $1}'`
# <LSI>1.2.3.4</LSI>
echo $LSIXML | awk -F '>' '{ print $2;}' | awk -F '<' '{print $1;}'
