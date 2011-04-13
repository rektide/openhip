QT += network \
    xml
QT -= gui
CONFIG += debug \
    dll
TARGET = hipmapcfg
TEMPLATE = lib
VERSION = 0.1.0
DEFINES += SMA_CRAWLER
# $(sysconfdir) grabs value of sysconfdir when Makefile is processed
DEFINES += SYSCONFDIR="\"\\\""$(sysconfdir)\\\"\""
DEFINES += DEBUG
LIBS += -L../../../if-map-qt/libifmap \
    -lifmap \
    -lxml2 \
    -lssl \
    -lcrypto
INCLUDEPATH += /usr/local/include/libifmap
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
