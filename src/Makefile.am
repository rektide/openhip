#
# Host Identity Protocol
# Copyright (c) 2006-2012 the Boeing Company
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
#  \file  src/Makefile.am
#
#  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
#
#  \brief  Automake makefile.
#

AUTOMAKE_OPTIONS=color-tests

sbin_PROGRAMS = hitgen hip hipstatus

# HIP protocol source files
SRC_PROTO = 	protocol/hip_addr.c protocol/hip_cache.c protocol/hip_dht.c \
		protocol/hip_globals.c protocol/hip_input.c \
		protocol/hip_ipsec.c protocol/hip_keymat.c protocol/hip_main.c \
		protocol/hip_output.c protocol/hip_status.c

# Utility source files
SRC_UTIL =	util/hip_util.c util/hip_xml.c

# Linux main files 
SRC_HIP =	linux/hip_linux_umh.c

# Hitgen source files
SRC_HITGEN = 	util/hitgen.c util/hip_util.c protocol/hip_globals.c

hitgen_CFLAGS =	-DHITGEN

# Usermode version
hip_CFLAGS =	
SRC_USERMODE =	usermode/hip_umh_main.c \
		usermode/hip_dns.c \
		usermode/hip_esp.c \
		usermode/hip_sadb.c \
		usermode/hip_status2.c \
		usermode/hip_mr.c

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

# different targets
hitgen_SOURCES = $(SRC_HITGEN)
hip_SOURCES = 	$(SRC_HIP) $(SRC_PROTO) $(SRC_UTIL) $(SRC_USERMODE)
hipstatus_SOURCES = util/usermode-status.c

AM_COLOR_TESTS=always
scriptdir=util/scripts
if WANT_VPLS
TESTS = $(scriptdir)/test-endbox.sh
else
TESTS = $(scriptdir)/test-bex.sh $(scriptdir)/test-mobility.sh \
	$(scriptdir)/test-rekey.sh
endif

.PHONY : shell
shell:
	python $(scriptdir)/hiptest.py shell


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

# Extra files to include with distribution tarball. The autoconf system does
# not know about some of the file used for WIN32, packaging, etc.
EXTRA_DIST = include linux util usermode/hip_nl.c win32

DISTCLEANFILES = Makefile.in util/Makefile.in 

