#!/bin/sh

set -e
set -x

autoreconf -i

if [ "x$LIBUSB" = "xwindows" ]; then
    ./configure --with-backend=stub
    touch ChangeLog
    make dist
    make -f ykpers4win.mk ykpers4win32 `grep ^VERSION Makefile|sed 's/ = /=/'`
else
    ./configure --with-backend=$LIBUSB
    make check
fi
