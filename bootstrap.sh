#!/bin/sh

# Test for prerequisites aclocal, autoheader automake, autoconf
PREREQS="aclocal autoheader automake autoconf"
for p in $PREREQS; do
    command -v $p >/dev/null 2>&1 || { echo >&2 "Command '$p' not found, aborting."; exit 1;}
done

# libtool is only used to build the configuration libraries associated
#  with the --enable-vpls configure option
if [ "$1a" = "--enable-vplsa" ]; then
	LIBTOOLIZE_MSG="echo '(1.5/3) Running libtoolize...'"
	LIBTOOLIZE="libtoolize --force --copy --automake"
	CONFOPTS=" --enable-vpls"
	if [ -e src/util/Makefile.am.disabled ]; then
		mv src/util/Makefile.am.disabled src/util/Makefile.am
	fi
	mv configure.ac configure.ac.orig
	sed -e "s,#AC_PROG_LIBTOOL,AC_PROG_LIBTOOL," configure.ac.orig > configure.ac
elif [ "$1a" = "cleana" ]; then
	echo "Cleaning up autoconf dirs..."
	rm -rf autom4te.cache config
	exit 0;
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
	echo "usage: ./bootstrap.sh [clean|--enable-vpls]"
	exit 1;
fi

if [ -d /usr/local/share/aclocal ]; then
	EXTRA_INC="-I /usr/local/share/aclocal"
else
	EXTRA_INC=""
fi;

if ! [ -d "config" ]; then
    mkdir config
fi

echo "(1/4) Running aclocal..." && aclocal -I config $EXTRA_INC \
    && echo "(2/4) Running autoheader..." && autoheader \
    && $LIBTOOLIZE_MSG && $LIBTOOLIZE \
    && echo "(3/4) Running automake..." \
    && automake --add-missing --copy --foreign \
    && echo "(4/4) Running autoconf..." && autoconf \
    && echo "" \
    && echo "You are now ready to run \"./configure\"$CONFOPTS."

