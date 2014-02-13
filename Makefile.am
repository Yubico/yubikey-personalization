# Written by Richard Levitte <richard@levitte.org>.
# Copyright (c) 2008-2013 Yubico AB
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

SUBDIRS= ykcore . tests

ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/ykcore -I$(srcdir)/rfc4634
AM_CFLAGS = $(WARN_CFLAGS)

AM_CFLAGS += $(libjson_CFLAGS)

# The library.

ykpers_includedir=$(includedir)/ykpers-1
ykpers_include_HEADERS = ykpers.h ykpers-version.h
ykpers_include_HEADERS += ykcore/ykstatus.h ykcore/ykcore.h ykcore/ykdef.h
ykpers_include_HEADERS += ykpbkdf2.h

lib_LTLIBRARIES = libykpers-1.la
libykpers_1_la_SOURCES = ykpers.c ykpers-version.c ykpbkdf2.c
if JSON
libykpers_1_la_SOURCES += ykpers-json.c
else
libykpers_1_la_SOURCES += ykpers-nojson.c
endif
libykpers_1_la_SOURCES += ykpers_lcl.h ykpers-json.h ykpers_lcl.c
libykpers_1_la_SOURCES += hmac.c usha.c sha.h sha1.c sha224-256.c \
	sha384-512.c sha-private.h
libykpers_1_la_SOURCES += ykpers-1.pc.in libykpers-1.map
libykpers_1_la_LIBADD = $(LTLIBYUBIKEY) ./ykcore/libykcore.la $(libjson_LIBS)
libykpers_1_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
EXTRA_libykpers_1_la_DEPENDENCIES = libykpers-1.map

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ykpers-1.pc

if HAVE_LD_VERSION_SCRIPT
libykpers_1_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libykpers-1.map
else
libykpers_1_la_LDFLAGS += -export-symbols-regex '^(ykp|yk|ykds|ykpers)_.*|_yk.*_errno_location'
endif

# The command line tools.

bin_PROGRAMS = ykpersonalize ykchalresp ykinfo

ykpersonalize_SOURCES = ykpersonalize.c ykpers-args.h ykpers-args.c
ykpersonalize_LDADD = ./libykpers-1.la $(LTLIBYUBIKEY)

ykchalresp_SOURCES = ykchalresp.c
ykchalresp_LDADD = ./libykpers-1.la $(LTLIBYUBIKEY)

ykinfo_SOURCES = ykinfo.c
ykinfo_LDADD = ./libykpers-1.la $(LTLIBYUBIKEY)

dist_man1_MANS = ykpersonalize.1 ykchalresp.1 ykinfo.1

# Dist docs from wiki.
EXTRA_DIST = doc/Compatibility.asciidoc doc/Make-Release.asciidoc doc/USB-Hid-Issue.asciidoc doc/Windows-Build.asciidoc

# Dist contrib stuff.
EXTRA_DIST += contrib/README contrib/programming.sh contrib/oath-unlock-reprogram.sh contrib/draft-josefsson-yubikey-config.xml

# Windows rules.
EXTRA_DIST += ykpers4win.mk ykpers4mac.mk

# Dist dev tools as well, to have the tarball complete.
EXTRA_DIST += build-and-test.sh .travis.yml .gitignore

# udev rule files
EXTRA_DIST += 69-yubikey.rules 70-yubikey.rules
udevrulesdir=@udevrulesdir@
dist_udevrules_DATA = \
        @udevrulesfile@

# Release

PROJECT = yubikey-personalization

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

check-doc-dist:
	perl -pe "s,^EXTRA_DIST = .*,EXTRA_DIST = `cd $(srcdir) && ls doc/*.asciidoc | xargs echo`," \
		 < $(srcdir)/Makefile.am > check-doc-dist.tmp
	diff -ur $(srcdir)/Makefile.am check-doc-dist.tmp || \
		(rm -f check-doc-dist.tmp; echo 'error: please update $(srcdir)/Makefile.am to include all docs'; exit 1)
	rm -f check-doc-dist.tmp
	! man --warnings ./*.1 2>&1 | grep ': warning'

release:
	@if test -z "$(KEYID)"; then \
		echo "Try this instead:"; \
		echo "  make release KEYID=[PGPKEYID]"; \
		echo "For example:"; \
		echo "  make release KEYID=2117364A"; \
		exit 1; \
	fi
	@head -3 $(srcdir)/NEWS | grep -q "Version $(VERSION) .released `date -I`" || \
		(echo 'error: You need to update date/version in $(srcdir)/NEWS, see doc/MakeRelease.wiki.'; exit 1)
	@if test ! -d "$(YUBICO_GITHUB_REPO)"; then \
		echo "yubico.github.com repo not found!"; \
		echo "Make sure that YUBICO_GITHUB_REPO is set"; \
		exit 1; \
	fi
	rm -f $(srcdir)/ChangeLog
	make check-doc-dist ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	cd $(srcdir) && git push
	cd $(srcdir) && git tag -u $(KEYID) -m $(VERSION) v$(VERSION)
	cd $(srcdir) && git push --tags
	$(YUBICO_GITHUB_REPO)/publish $(PROJECT) $(VERSION) $(PACKAGE)-$(VERSION).tar.gz*
