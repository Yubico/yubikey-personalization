# Written by Richard Levitte <richard@levitte.org>.
# Copyright (c) 2008, 2009, Yubico AB
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# 
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
# 
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

AC_INIT([yubikey-personalization], [0.91],
  [yubico-devel@googlegroups.com], [ykpers],
  [http://code.google.com/p/yubikey-personalization/])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
AC_SUBST(LT_CURRENT, 1)
AC_SUBST(LT_REVISION, 0)
AC_SUBST(LT_AGE, 0)

AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

AC_LIB_HAVE_LINKFLAGS(yubikey,,
  [#include <yubikey.h>],
  [yubikey_modhex_decode(0,0,0)])
if test "$ac_cv_libyubikey" != yes; then
  AC_MSG_ERROR([libyubikey not found, see http://code.google.com/p/yubico-c/])
fi

AC_ARG_WITH([backend],
  [AS_HELP_STRING([--with-backend=ARG],
    [use specific backend; 'libusb' or 'osx'])])
AC_MSG_CHECKING([for backend])
if test x$with_backend != xosx && test x$with_backend != xlibusb; then
  AC_CANONICAL_HOST
  case "$host" in
    *-darwin*) with_backend=osx ;;
    *) with_backend=libusb ;;
  esac
fi
AC_MSG_RESULT([$with_backend])
AM_CONDITIONAL([BACKEND_LIBUSB], test x$with_backend = xlibusb)
AM_CONDITIONAL([BACKEND_OSX], test x$with_backend = xosx)

if test x$with_backend = libusb; then
  AC_LIB_HAVE_LINKFLAGS(usb,, [#include <usb.h>], [usb_init()])
  if test "$ac_cv_libusb" != yes; then
     AC_MSG_ERROR([libusb not found, please install usb.h and libusb.so])
  fi
fi

AC_CONFIG_FILES([
  Makefile
  ykcore/Makefile
])
AC_OUTPUT
