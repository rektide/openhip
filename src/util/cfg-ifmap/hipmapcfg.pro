QT += network \
    xml
QT -= gui
CONFIG += debug \
    dll
TARGET = hipmapcfg
TEMPLATE = lib
VERSION = 0.1.0
DEFINES += SMA_CRAWLER
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