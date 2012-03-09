#
# Host Identity Protocol
# Copyright (c) 2006-2011 the Boeing Company
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Makefile.am
#
# Author: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
#
#

sbin_PROGRAMS = hitgen hip hipstatus
if WANT_KERNEL
sbin_PROGRAMS += hipd
endif

# HIP protocol source files
SRC_PROTO = 	protocol/hip_addr.c protocol/hip_cache.c protocol/hip_dht.c \
		protocol/hip_globals.c protocol/hip_input.c \
		protocol/hip_ipsec.c protocol/hip_keymat.c protocol/hip_main.c \
		protocol/hip_output.c protocol/hip_status.c

# Utility source files
SRC_UTIL =	util/hip_util.c util/hip_xml.c

# Linux main files 
SRC_MAIN_KERN = linux/hip_linux_main.c
SRC_MAIN_UMH =	linux/hip_linux_umh.c

# Hitgen source files
SRC_HITGEN = 	util/hitgen.c util/hip_util.c protocol/hip_globals.c

hitgen_CFLAGS =	-DHITGEN
if !WANT_KERNEL
hitgen_CFLAGS += -D__UMH__
endif

# Usermode version
hip_CFLAGS =	-D__UMH__
SRC_USERMODE =	usermode/hip_umh_main.c \
		usermode/hip_dns.c  usermode/hip_pfkey.c \
		usermode/libipsec_stub.c usermode/hip_esp.c \
		usermode/hip_sadb.c   usermode/hip_status2.c
if WANT_MOBILE_ROUTER
SRC_USERMODE += usermode/hip_mr.c
endif

# Mac support
if WANT_OSX
hip_CFLAGS += -D__MACOSX__
hitgen_CFLAGS += -D__MACOSX__
hipstatus_CFLAGS = -D__MACOSX__
SRC_USERMODE += mac/hip_mac.c
endif

INCLUDES = -I./include @libxml2_CFLAGS@
LDADD = @libxml2_LIBS@ -lz -ldl

# VPLS support
if WANT_VPLS
SRC_USERMODE += usermode/hip_endbox.c
SRC_UTIL +=	util/cfg-api/hip_cfg_api.c
SUBDIRS = util
endif

# i3 support
SRC_PROTO_I3 = protocol/i3_send.c protocol/i3_recv.c

# different targets
hitgen_SOURCES = $(SRC_HITGEN)
hipd_SOURCES =	$(SRC_PROTO) $(SRC_UTIL) $(SRC_MAIN_KERN)
hip_SOURCES = 	$(SRC_PROTO) $(SRC_UTIL) $(SRC_MAIN_UMH) $(SRC_USERMODE)
hipstatus_SOURCES = util/usermode-status.c

# this would be nice to use, but it overwrites the file upon 'make install'
#dist_sysconf_DATA = ../conf/known_host_identities.xml
	
# make sure that HIP directories are available
install-data-hook:
	test -d "$(DESTDIR)$(localstatedir)/log" || \
		mkdir -p "$(DESTDIR)$(localstatedir)/log"
	test -d "$(DESTDIR)$(localstatedir)/run" || \
		mkdir -p "$(DESTDIR)$(localstatedir)/run"
	test -d "$(DESTDIR)$(sysconfdir)" || mkdir -p "$(DESTDIR)$(sysconfdir)"
	test -e "$(DESTDIR)$(sysconfdir)/known_host_identities.xml" || \
		cp ../conf/known_host_identities.xml $(DESTDIR)$(sysconfdir)
	@echo 
	@echo Configuration files will reside in $(DESTDIR)$(sysconfdir).
	@echo " - run $(DESTDIR)$(sbindir)/hitgen -conf to generate"
	@echo "   a default $(DESTDIR)$(sysconfdir)/hip.conf file."
	@echo " - run $(DESTDIR)$(sbindir)/hitgen (no parameters) to generate"
	@echo "   a $(DESTDIR)$(sysconfdir)/my_host_identities.xml file."
	@echo

