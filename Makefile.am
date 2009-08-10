# Written by Richard Levitte <richard@levitte.org>.
# Copyright (c) 2008, 2009 Yubico AB
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

# Subdirectories

SUBDIRS=ykcore

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/ykcore -I$(srcdir)/rfc4634

# The library.

include_HEADERS = ykpers.h ykcore/ykstatus.h ykcore/ykcore.h

lib_LTLIBRARIES = libykpers.la
libykpers_la_SOURCES = ykpers.c ykpbkdf2.h ykpbkdf2.c
libykpers_la_SOURCES += rfc4634/hmac.c rfc4634/usha.c rfc4634/sha.h	\
	rfc4634/sha1.c rfc4634/sha224-256.c rfc4634/sha384-512.c	\
	rfc4634/sha-private.h
libykpers_la_LIBADD = $(LTLIBYUBIKEY) ./ykcore/libykcore.la
libykpers_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

# The command line tools.

bin_PROGRAMS = ykpersonalize

ykpersonalize_SOURCES = ykpersonalize.c
ykpersonalize_LDADD = ./libykpers.la ./ykcore/libykcore.la

man1_MANS = ykpersonalize.1

# Self tests.

AM_LDFLAGS = -no-install
LDADD = ./libykpers.la

ctests = selftest$(EXEEXT)
check_PROGRAMS = $(ctests)
TESTS = $(ctests)

# Dist docs from wiki.
EXTRA_DIST = doc/MakeRelease.wiki doc/ReadMe.wiki doc/UsbhidIssue.wiki

# Release

PROJECT = yubikey-personalization
USER = simon75j
KEYID = B9156397

ChangeLog:
	svn2cl

check-doc-dist:
	perl -pe "s,^EXTRA_DIST = .*,EXTRA_DIST = `echo doc/*.wiki`," < Makefile.am > tmp
	diff -ur Makefile.am tmp || (echo 'error: please update Makefile.am'; exit 1)

release:
	rm -f ChangeLog
	make check-doc-dist ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	svn copy https://$(PROJECT).googlecode.com/svn/trunk/ \
	 https://$(PROJECT).googlecode.com/svn/tags/$(PACKAGE)-$(VERSION) \
	 -m "Tagging the $(VERSION) release of the $(PACKAGE) project."
	googlecode_upload.py -s "OpenPGP signature for $(PACKAGE) $(VERSION)." \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION).tar.gz.sig
	googlecode_upload.py -s "$(PACKAGE) $(VERSION)" \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION).tar.gz 
