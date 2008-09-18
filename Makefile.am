# Written by Richard Levitte <richard@levitte.org>.
# Copyright (c) 2008 Yubico AB
# All rights reserved.
#
# Copyright (c) 2008, Yubico AB
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

# The library.

HEADERS = ykpers.h
lib_LTLIBRARIES = libykpers.la
libyubikey_la_SOURCES = ykpers.h ykpers.c
libyubikey_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

# The command line tools.

bin_PROGRAMS = ykpersonalize

ykpersonalize_SOURCES = ykpersonalize.c
modhex_LDADD = ./libykpers.la

# Self tests.

AM_LDFLAGS = -no-install
LDADD = libykpers.la

check_PROGRAMS = selftest
TESTS = $(check_PROGRAMS)

# Release

#EXTRA_DIST = simple.mk

ChangeLog:
	svn2cl

release:
	rm -f ChangeLog
	make ChangeLog distcheck
	svn copy https://$(PACKAGE).googlecode.com/svn/trunk/ \
	 https://$(PACKAGE).googlecode.com/svn/tags/$(PACKAGE)-$(VERSION) \
	 -m "Tagging the $(VERSION) release of the $(PACKAGE) project."
	googlecode_upload.py -s "Yubico Key personalization library v$(VERSION)." \
	 -p $(PACKAGE) -u levitte $(PACKAGE)-$(VERSION).tar.gz 
