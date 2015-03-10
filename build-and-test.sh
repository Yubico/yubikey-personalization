#!/bin/sh

set -e
set -x

autoreconf -i

if [ "x$LIBUSB" = "xwindows" ]; then
    ./configure --with-backend=stub
    touch ChangeLog
    make dist

    if [ "x$ARCH" = "x32" ]; then
        export CC=i686-w64-mingw32-gcc
    else
        export CC=x86_64-w64-mingw32-gcc
    fi
    make -f ykpers4win.mk ykpers4win${ARCH} `grep ^VERSION Makefile|sed 's/ = /=/'`
else
    ./configure --with-backend=$LIBUSB $COVERAGE
    make check
    if [ "x$COVERAGE" != "x" ]; then
        gem install coveralls-lcov
        coveralls-lcov coverage/app2.info
    fi
fi
