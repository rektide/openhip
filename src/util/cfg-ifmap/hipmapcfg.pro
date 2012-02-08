#
# Host Identity Protocol
# Copyright (c) 2011-2012 the Boeing Company
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#  \file hipmapcfg.pro
#
#  \authors  David Mattes <david.mattes@boeing.com>
#
#  \brief  QT Makefile for ifmap library.
#


QT += network \
    xml
QT -= gui
CONFIG += debug \
    dll
TARGET = hipmapcfg
TEMPLATE = lib
VERSION = $$[LIBVERSION]
DEFINES += HIP_VPLS
DEFINES += DEBUG
LIBS += -lifmap \
    -lxml2 \
    -lssl \
    -lcrypto

linux-mips-g++|linux-arm-g++ {
    # This qmake scope supports OpenWRT builds for ARM/MIPS devices.
    # $$[SYSCONFDIR] is passed in with: `qmake -set SYSCONFDIR /usr/local/etc/hip`
    DEFINES += SYSCONFDIR="\"\\\""$$[SYSCONFDIR]\\\"\""

    LIBS += -L$$[STAGINGDIR]/usr/local/lib -lifmap
    LIBS += -L$$[STAGINGDIR]/usr/lib -lxml2 -lssl -lcrypto

    # $$[STAGINGDIR] is passed in with: `qmake -set STAGINGDIR /path/to/staging/dir`
    INCLUDEPATH += $$[STAGINGDIR]/usr/local/include/libifmap
    INCLUDEPATH += $$[STAGINGDIR]/usr/include/
    INCLUDEPATH += $$[STAGINGDIR]/usr/include/libxml2
    INCLUDEPATH += $$[STAGINGDIR]/usr/include/openssl
    # $$[BUILDDIR] is passed in with: `qmake -set BUILDDIR /path/to/build/dir`
    #INCLUDEPATH += $$[BUILDDIR]/openhip-boeing-0.6.0/src/include
    #INCLUDEPATH += $$[BUILDDIR]/openhip-boeing-0.6.0/src/include/hip
} else {
    # $(sysconfdir) grabs value of sysconfdir when Makefile is processed
    DEFINES += SYSCONFDIR="\"\\\""$(sysconfdir)\\\"\""

    INCLUDEPATH += /usr/local/include/libifmap
    INCLUDEPATH += /usr/include/libxml2
}

INCLUDEPATH += ../../include
INCLUDEPATH += ../../include/hip

SOURCES += hip_cfg_map.cpp \
    ifmap_client.cpp \
    ifmap_thread.cpp \
    ../cfg-common/hip_cfg.cpp
HEADERS += ifmap_client.h \
    ifmap_thread.h \
    ../../include/hip/hip_cfg_map.h

#DESTDIR = /usr/local/lib
