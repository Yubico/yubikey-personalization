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

AC_INIT([yubikey-personalization], [1.0], [yubico-devel@googlegroups.com], [ykpers],
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

AC_ARG_WITH([usb], [ AS_HELP_STRING([--with-usb], [set libusb root path])])

AM_INIT_AUTOMAKE([-Wall -Werror])
AC_PROG_CC
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

# This really checks a directory
AC_CHECK_FILES([yubikey-core/configure.ac yubikey-core/ykcore.h],,AC_MSG_FAILURE(yubikey-core directory not found.

************************************
Please provide by checking out http://yubikey-core.googlecode.com/svn/trunk
with svn and creating a symbolic link `yubikey-core' to that checkout
************************************
))
#AC_SEARCH_LIBS([yubikey_parse],[yubikey],,AC_MSG_FAILURE(libyubikey not found))

# Check that the yubikey-core we try to use is modern enough
AC_MSG_CHECKING(if yubikey-core/ykcore.h declares yk_usb_strerror)
AC_EGREP_CPP([yk_usb_strerror],
	     [#include "yubikey-core/ykcore.h"],
	     AC_MSG_RESULT(yes),
	     AC_MSG_RESULT(no)
	     AC_MSG_FAILURE(yubikey-core/ykcore.h does not declare yk_usb_strerror.
You probably need to update yubikey-core))

if test "$with_usb" != "yes"; then
  if test "$with_usb" != ""; then
    CFLAGS="$CFLAGS -I$with_usb/include"
    CXXFLAGS="$CXXFLAGS -I$with_usb/include"
    CPPFLAGS="$CPPFLAGS -I$with_usb/include"
    LIBS="$LIBS -L$with_usb/lib"
  fi
fi

AC_CHECK_HEADER([usb.h])
AC_CHECK_LIB([usb], [usb_init])

if test "$ac_cv_header_usb_h" == no; then
  AC_MSG_WARN([Missing libusb])
fi

AC_LIB_HAVE_LINKFLAGS(yubikey,, [#include <yubikey.h>],
				[yubikey_modhex_decode(0,0,0)])
if test "$ac_cv_libyubikey" != yes; then
   AC_MSG_ERROR([libyubikey not found, see http://code.google.com/p/yubico-c/])
fi

AC_CONFIG_SUBDIRS(yubikey-core)
AC_CONFIG_FILES(Makefile)
AC_OUTPUT
