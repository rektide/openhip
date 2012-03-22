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
#  \file  configure.ac
#
#  \authors  Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
#
#  \brief  Process this file with autoconf to produce a configure script.
#                                               -*- Autoconf -*-

AC_PREREQ(2.59)
# change the HIP version here
AC_INIT(OpenHIP, 0.9, [openhip-developers@lists.sourceforge.net], openhip)
AC_CONFIG_SRCDIR([src/protocol/hip_main.c])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR(config)
AM_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

# Default compiler flags, to avoid using -g with release files.
# GNU_SOURCE is defined so we have the IPv6 pktinfo structure
# -fno-strict-aliasing fixes gcc 4.4 problems with macros such as SA2IP
AC_GNU_SOURCE
CFLAGS="$CFLAGS -O3 -Werror -D_GNU_SOURCE -fno-strict-aliasing"

# HIP files go in /etc/hip or /usr/local/etc/hip
sysconfdir=$sysconfdir/hip
# HIP state directory for /var/log/hip.log and /var/run/hip.pid
if test "$localstatedir" = "\${prefix}/var" ; then
  # use /var instead of /usr/local/var (/usr/local/var/log isn't standard)
  localstatedir="/var"
fi
 

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
#AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([crypto], [AES_cbc_encrypt])
if test "x$ac_cv_lib_crypto_AES_cbc_encrypt" != "xyes"; then
	AC_MSG_ERROR([Could not find AES functions from OpenSSL. Make sure the openssl-devel package is installed or that you have installed the suitable source.])
fi
AC_CHECK_LIB([crypto], [RSA_verify])
if test "x$ac_cv_lib_crypto_RSA_verify" != "xyes"; then
	AC_MSG_ERROR([Could not find RSA functions from OpenSSL. Make sure the openssl-devel package is installed or that you have installed the suitable source.])
fi

AC_CHECK_LIB([pthread], [pthread_create])

# the simple check below does not work; this could be improved
#AC_CHECK_LIB([m], [pow])
LIBS="$LIBS -lm"

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero gethostbyname gethostname gettimeofday inet_ntoa memmove memset pow select socket strchr strerror strncasecmp strrchr strstr uname])

CFLAGS="$CFLAGS -Wall -DCONFIG_HIP -DSYSCONFDIR=\"\\\"\$(sysconfdir)\\\"\" -DLOCALSTATEDIR=\"\\\"\$(localstatedir)\\\"\"  "

AC_MSG_CHECKING(if --enable-vpls option is specified)
AC_ARG_ENABLE(vpls,
	[  --enable-vpls=config  enable VPLS with configuration via {files, IFMAP}],
	[enable_vpls=$enable_vpls
	 AC_MSG_RESULT(yes)],
	[enable_vpls=default
	 AC_MSG_RESULT(no)])

#
# configure option to define HIP_VPLS
################################################################################
if test "$enable_vpls" = "yes"; then
	enable_vpls="files" ;# default value
fi
if test "$enable_vpls" = "files" -o "$enable_vpls" = "IFMAP"; then
	want_vpls=true
	want_vpls_files_cfg=false
	want_vpls_IFMAP_cfg=false
	CFLAGS=" -DHIP_VPLS $CFLAGS"

	AC_CHECK_LIB([ssl], [SSL_library_init])
	if test "x$ac_cv_lib_ssl_SSL_library_init" = "xyes"; then
		AC_MSG_RESULT(
			[OpenSSL library found for VPLS extensions])
	else
		AC_MSG_ERROR(
			[VPLS extensions requested but OpenSSL library not found.])
	fi

	if test "$enable_vpls" = "files"; then
		AC_MSG_RESULT([Will use file-based configuration library libhipcfgfiles.so])
		want_vpls_files_cfg=true
	elif test "$enable_vpls" = "IFMAP"; then
		AC_MSG_RESULT([Will use IFMAP-based configuration library libhipcfgmap.so])
		want_vpls_IFMAP_cfg=true
	fi

else
       want_vpls=false
fi

#
# Mac OS X detection 
################################################################################
want_osx=false
case "${host}" in
  *-apple-darwin*)
    want_osx=true
    ;;
esac

# Automake conditionals
################################################################################
AM_CONDITIONAL(WANT_OSX, test x$want_osx = xtrue)
AM_CONDITIONAL(WANT_VPLS, test x$want_vpls = xtrue)
AM_CONDITIONAL(WANT_VPLS_FILES_CFG, 
	test x$want_vpls_files_cfg = xtrue)
AM_CONDITIONAL(WANT_VPLS_IFMAP_CFG,
	test x$want_vpls_IFMAP_cfg = xtrue)

PKG_CHECK_MODULES(libxml2, libxml-2.0)

AC_CONFIG_FILES([src/include/hip/hip_version.h
		 src/linux/openhip.spec
		 src/win32/install-win32/openhip.nsi
		 docs/Doxyfile
		 Makefile
                 src/Makefile
		 src/util/Makefile
		 docs/Makefile])
AC_OUTPUT

#
# Summary message at the end of configure output. Keep this pretty.
################################################################################
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([=== Finished configuring $PACKAGE_STRING: ===])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([    - building HIP user mode binary 'hip'])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([    - building 'hitgen' utility])
AC_MSG_NOTICE([ ])

if test $want_vpls = true; then
	AC_MSG_NOTICE([    - building virtual private LAN service extensions])
	AC_MSG_NOTICE([    	- will use $enable_vpls-based configuration library])
else
	AC_MSG_NOTICE([    - NOT building virtual private LAN service extensions])
fi
AC_MSG_NOTICE([ ])

