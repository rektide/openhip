#!/bin/sh

# libtool is only used to build the configuration libraries associated
#  with the --enable-sma-crawler configure option
if [ "$1a" = "--enable-sma-crawlera" ]; then
	LIBTOOLIZE_MSG="echo Running libtoolize..."
	LIBTOOLIZE="libtoolize --force --copy --automake"
	CONFOPTS=" --enable-sma-crawler"
	if [ -e src/util/Makefile.am.disabled ]; then
		mv src/util/Makefile.am.disabled src/util/Makefile.am
	fi
	mv configure.ac configure.ac.orig
	sed -e "s,#AC_PROG_LIBTOOL,AC_PROG_LIBTOOL," configure.ac.orig > configure.ac
elif [ "$1a" = "a" ]; then
	LIBTOOLIZE_MSG=""
	LIBTOOLIZE=""
	CONFOPTS=""
	if [ ! -e src/util/Makefile.am.disabled ]; then
		mv src/util/Makefile.am src/util/Makefile.am.disabled
		touch src/util/Makefile.am
	fi
	if [ -e configure.ac.orig ]; then
		mv configure.ac.orig configure.ac
	fi
else
	echo "usage: ./bootstrap.sh [--enable-sma-crawler]"
	exit 1;
fi

if [ -d /usr/local/share/aclocal ]; then
	EXTRA_INC="-I /usr/local/share/aclocal"
else
	EXTRA_INC=""
fi;

echo "Running aclocal..." && aclocal $EXTRA_INC \
    && $LIBTOOLIZE_MSG && $LIBTOOLIZE \
    && echo "Running automake..." && automake --add-missing --copy --foreign \
    && echo "Running autoconf..." && autoconf \
    && echo "" \
    && echo "You are now ready to run \"./configure\"$CONFOPTS."

