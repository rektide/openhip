#!/bin/sh
if [ -d /usr/local/share/aclocal ]; then
	EXTRA_INC="-I /usr/local/share/aclocal"
else
	EXTRA_INC=""
fi;
LIBTOOLIZE="libtoolize --force --copy --automake"
if [ `uname` = Darwin ]; then
	echo "Using Mac OS X Makefile."
	mv -n src/Makefile.am src/Makefile.orig.am
	cp src/Makefile.mac.am src/Makefile.am
	# don't run libtoolize on Mac
	LIBTOOLIZE="echo -n ' '"
fi;

echo "Running aclocal..." && aclocal $EXTRA_INC \
    && echo "Running libtoolize..." && $LIBTOOLIZE \
    && echo "Running automake..." && automake --add-missing --copy --foreign \
    && echo "Running autoconf..." && autoconf

echo ""
echo "You are now ready to run \"./configure\"."

