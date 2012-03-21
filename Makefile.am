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
#  \file  Makefile.am
#
#  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
#
#  \brief Top level automake Makefile.
#

SUBDIRS = src docs
TARGETS = 

ACLOCAL_AMFLAGS = -I config

# Extra files to include with distribution tarball. The autoconf system does
# not know about some of the file used for WIN32, packaging, etc.
EXTRA_DIST = bootstrap.sh LICENSE README RELEASE_NOTES patches conf \
	     Makefile.msvc

DISTCLEANFILES = stamp-h1 aclocal.m4 config.h.in configure Makefile.in

dist-hook:
	rm -rf `find $(distdir)/ -type d -name .svn`

.PHONY: deb
deb:
	mkdir -p debian
	cp -vf src/linux/deb/* debian/
	@echo "Ready to run pbuilder."

.PHONY: rpm
rpm:
	rpmdev-setuptree
	cp -afv openhip-*.tar.gz ~/rpmbuild/SOURCES
	cp -afv src/linux/openhip.spec ~/rpmbuild/SPECS
	rpmbuild -bs ~/rpmbuild/SPECS/openhip.spec

