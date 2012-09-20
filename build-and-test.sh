#!/bin/sh

set -e

autoreconf -i

if [ "x$LIBUSB" = "xwindows" ]; then
  ./configure --with-backend=stub
  touch ChangeLog
  make dist
  make -f ykpers4win.mk ykpers4win32mingw32
else
  ./configure --with-backend=$LIBUSB
  make check
fi
