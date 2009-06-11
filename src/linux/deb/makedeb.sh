#!/bin/sh
#
# (c)2007 the Boeing Company
#
# makedeb.sh
# Author: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
#
# simple script to generate a deb package
# 
#!/bin/sh


# assume we are running in src/linux/debian
MYDIR=$PWD
SRC=../..

# build HIP code
echo Building HIP binaries...
cd $SRC/..
./bootstrap.sh && ./configure && make

# get version number and remove quotes
HIPVER=`grep define\ HIP_VER src/include/hip/hip_version.h | awk {'gsub(/"/,a,$3); print $3'};`
# use this one for version number without quotes (float)
#HIPVER=`grep define\ HIP_VER src/include/hip/hip_version.h | awk {'print $3'};`
echo Detected version $HIPVER

echo Collecting files for data.tar.gz...
cd $MYDIR
mkdir tmp
mkdir tmp/DEBIAN
cd tmp
mkdir -p usr/local/sbin
mkdir -p usr/local/etc/hip
mkdir -p usr/share/doc/openhip-$HIPVER

cp -p ${PWD}/${SRC}/../hip usr/local/sbin
cp -p ${PWD}/${SRC}/../hitgen usr/local/sbin
cp -p ${PWD}/${SRC}/../../conf/known_host_identities.xml usr/local/etc/hip
cp -p ${PWD}/${SRC}/../../AUTHORS usr/share/doc/openhip-$HIPVER
cp -p ${PWD}/${SRC}/../../README usr/share/doc/openhip-$HIPVER
cp -p ${PWD}/${SRC}/../../LICENSE usr/share/doc/openhip-$HIPVER

find usr -type f -exec md5sum {} \; > ./DEBIAN/md5sums

echo Collecting control files...
cd $MYDIR
cp -p control tmp/DEBIAN
cp -p conffiles tmp/DEBIAN
cp -p postinst tmp/DEBIAN
chmod +x tmp/DEBIAN/postinst

echo Generating DEB file...
cd $MYDIR
dpkg-deb -b tmp openhip_${HIPVER}_i386.deb
