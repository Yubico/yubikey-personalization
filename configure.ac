# Written by Richard Levitte <richard@levitte.org>.
# Copyright (c) 2008, 2009, 2010, Yubico AB
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

AC_INIT([yubikey-personalization], [1.3.3],
  [yubico-devel@googlegroups.com], [ykpers],
  [http://code.google.com/p/yubikey-personalization/])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
AC_SUBST(LT_CURRENT, 2)
AC_SUBST(LT_REVISION, 0)
AC_SUBST(LT_AGE, 1)

AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC

ACX_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"

AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AC_CANONICAL_HOST
PKG_PROG_PKG_CONFIG

AC_LIB_HAVE_LINKFLAGS(yubikey,,
  [#include <yubikey.h>],
  [yubikey_modhex_p("foo")])
if test "$ac_cv_libyubikey" != yes; then
  AC_MSG_ERROR([libyubikey v1.5+ not found, see http://code.google.com/p/yubico-c/])
fi

AC_ARG_WITH([backend],
  [AS_HELP_STRING([--with-backend=ARG],
    [use specific backend; 'libusb-1.0', 'libusb' or 'osx'])],
    [],
    [with_backend=check])

if test "x$with_backend" = xcheck; then
   with_backend_orig=check
   AC_MSG_CHECKING([for backend])
   case "$host" in
    *-darwin*) with_backend=osx ;;
    *) PKG_CHECK_EXISTS([libusb-1.0], 
       			   [with_backend=libusb-1.0],
			   [with_backend=libusb])
  esac
  AC_MSG_RESULT([$with_backend])
fi
AM_CONDITIONAL([BACKEND_LIBUSB], test x$with_backend = xlibusb)
AM_CONDITIONAL([BACKEND_LIBUSB_1_0], test x$with_backend = xlibusb-1.0)
AM_CONDITIONAL([BACKEND_OSX], test x$with_backend = xosx)

if test "x$with_backend" = "xlibusb-1.0"; then
   PKG_CHECK_MODULES([LIBUSB], [libusb-1.0])
fi

if test x$with_backend = xlibusb; then
  AC_LIB_HAVE_LINKFLAGS(usb,, [#include <usb.h>], [usb_init()])
  if test "$ac_cv_libusb" != yes; then
    if test "$with_backend_orig" = "check"; then
     AC_MSG_ERROR([libusb-1.0 or libusb not found, please install one of them])
    else
      AC_MSG_ERROR([libusb not found, please install usb.h and libusb.so])
    fi
  fi
fi

if test x$with_backend = xosx; then
  LDFLAGS="$LDFLAGS -framework IOKit -framework CoreFoundation"
fi

gl_LD_VERSION_SCRIPT

AC_CONFIG_FILES([
  Makefile
  ykpers-1.pc
  ykcore/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

  version:          ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE
  Host type:        ${host}
  Install prefix:   ${prefix}
  Compiler:         ${CC}
  Library types:    Shared=${enable_shared}, Static=${enable_static}
  USB backend:      ${with_backend}
])
