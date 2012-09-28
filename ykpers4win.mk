# Written by Simon Josefsson <simon@josefsson.org>.
# Copyright (c) 2010-2012 Yubico AB
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

LIBYUBIKEYVERSION=1.9
PROJECT=yubikey-personalization
PACKAGE=ykpers
VERSION=1.8.1

all: usage ykpers4win32 ykpers4win64

.PHONY: usage
usage:
	@if test -z "$(USER)" || test -z "$(VERSION)" || test -z "$(PGPKEYID)"; then \
		echo "Try this instead:"; \
		echo "  make USER=[GOOGLEUSERNAME] PGPKEYID=[PGPKEYID] VERSION=[VERSION]"; \
		echo "For example:"; \
		echo "  make USER=simonyubico@gmail.com PGPKEYID=2117364A VERSION=1.6.0"; \
		exit 1; \
	fi

ykpers4win:
	rm -rf tmp && mkdir tmp && cd tmp && \
	cp ../libyubikey-$(LIBYUBIKEYVERSION).tar.gz . \
		|| 	wget http://yubico-c.googlecode.com/files/libyubikey-$(LIBYUBIKEYVERSION).tar.gz && \
	tar xfa libyubikey-$(LIBYUBIKEYVERSION).tar.gz && \
	cd libyubikey-$(LIBYUBIKEYVERSION) && \
	./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root && \
	make install $(CHECK) && \
	cd .. && \
	cp ../ykpers-$(VERSION).tar.gz . \
		|| wget http://yubikey-personalization.googlecode.com/files/ykpers-$(VERSION).tar.gz && \
	tar xfa ykpers-$(VERSION).tar.gz && \
	cd ykpers-$(VERSION)/ && \
	lt_cv_deplibs_check_method=pass_all ./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root LDFLAGS=-L$(PWD)/tmp/root/lib CPPFLAGS=-I$(PWD)/tmp/root/include && \
	make install $(CHECK) && \
	cd .. && \
	cd root && \
	zip -r ../../ykpers-$(VERSION)-win$(ARCH).zip *

ykpers4win32:
	$(MAKE) -f ykpers4win.mk ykpers4win ARCH=32 HOST=i686-w64-mingw32 CHECK=check

ykpers4win64:
	$(MAKE) -f ykpers4win.mk ykpers4win ARCH=64 HOST=x86_64-w64-mingw32 CHECK=check

ykpers4win32mingw32:
	$(MAKE) -f ykpers4win.mk ykpers4win ARCH=32 HOST=i586-mingw32msvc CHECK=check CC=i586-mingw32msvc-gcc CFLAGS=-I/usr/i586-mingw32msvc/include/ddk/

upload-ykpers4win:
	gpg --detach-sign --default-key $(PGPKEYID) \
		$(PACKAGE)-$(VERSION)-win$(BITS).zip
	gpg --verify $(PACKAGE)-$(VERSION)-win$(BITS).zip.sig
	googlecode_upload.py \
	 -s "OpenPGP signature for $(PACKAGE)-$(VERSION)-win$(BITS).zip." \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION)-win$(BITS).zip.sig
	googlecode_upload.py \
	 -s "Windows $(BITS)-bit binaries of $(PACKAGE) $(VERSION)" \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION)-win$(BITS).zip

upload-ykpers4win32:
	$(MAKE) -f ykpers4win.mk upload-ykpers4win BITS=32

upload-ykpers4win64:
	$(MAKE) -f ykpers4win.mk upload-ykpers4win BITS=64
