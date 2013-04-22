#!/bin/sh

set -e
set -x

autoreconf -i

if [ "x$LIBUSB" = "xwindows" ]; then
    if [ "x$ARCH" = "x32" ]; then
        export CC=i686-w64-mingw32-gcc
    else
        export CC=x86_64-w64-mingw32-gcc
    fi
    ./configure --with-backend=stub
    touch ChangeLog
    make dist
    make -f ykpers4win.mk ykpers4win${ARCH} `grep ^VERSION Makefile|sed 's/ = /=/'`
else
    ./configure --with-backend=$LIBUSB
    make check
fi
