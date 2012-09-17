# Copyright (c) 2008-2012 Yubico AB
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

noinst_LTLIBRARIES = libykcore.la
libykcore_la_SOURCES = ykdef.h ykcore.h ykcore_lcl.h ykcore_backend.h	\
	ykcore.c ykstatus.h ykstatus.c yktsd.h
libykcore_la_LIBADD = $(LTLIBYUBIKEY) $(LTLIBUSB) @LIBUSB_LIBS@
AM_CFLAGS = $(WARN_CFLAGS)

if BACKEND_LIBUSB_1_0
libykcore_la_SOURCES += ykcore_libusb-1.0.c
AM_CFLAGS += @LIBUSB_CFLAGS@
endif

if BACKEND_LIBUSB
libykcore_la_SOURCES += ykcore_libusb.c
endif

if BACKEND_OSX
libykcore_la_SOURCES += ykcore_osx.c
endif

if BACKEND_WINDOWS
libykcore_la_SOURCES += ykcore_windows.c
endif

EXTRA_DIST = ykcore_stub.c
