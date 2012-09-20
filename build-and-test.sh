#!/bin/sh

set -e

autoreconf -i

if [ "x$LIBUSB" = "xwin32" ]; then
  ./configure --with-backend=stub
  touch ChangeLog
  make dist
  make -f ykpers4win.mk ykpers4win32
elif [ "x$LIBUSB" = "xwin64" ]; then
  ./configure --with-backend=stub
  touch ChangeLog
  make dist
  make -f ykpers4win.mk ykpers4win64
else
  ./configure --with-backend=$LIBUSB
  make check
fi
