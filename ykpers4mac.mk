# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
# Base copied from ykpers4win.mk
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

LIBYUBIKEYVERSION=1.10
LIBJSONVERSION=0.11-20130402
PROJECT=yubikey-personalization
PACKAGE=ykpers

all: usage ykpers4mac

.PHONY: usage
usage:
	@if test -z "$(USER)" || test -z "$(VERSION)" || test -z "$(PGPKEYID)"; then \
		echo "Try this instead:"; \
		echo "  make USER=[GOOGLEUSERNAME] PGPKEYID=[PGPKEYID] VERSION=[VERSION]"; \
		echo "For example:"; \
		echo "  make USER=simonyubico@gmail.com PGPKEYID=2117364A VERSION=1.6.0"; \
		exit 1; \
	fi

ykpers4mac:
	rm -rf tmp && mkdir tmp && cd tmp && \
	mkdir -p root/licenses && \
	cp ../json-c-$(LIBJSONVERSION) . \
		||	wget --no-check-certificate https://github.com/json-c/json-c/tarball/json-c-$(LIBJSONVERSION) && \
	tar xfz json-c-$(LIBJSONVERSION) && \
	cd json-c-json-c-* && \
	./configure --prefix=$(PWD)/tmp/root && \
	make install $(CHECK) && \
	install_name_tool -id @executable_path/../lib/libjson-c.2.dylib $(PWD)/tmp/root/lib/libjson-c.2.dylib && \
	install_name_tool -id @executable_path/../lib/libjson-c.2.dylib $(PWD)/tmp/root/lib/libjson-c.dylib && \
	install_name_tool -id @executable_path/../lib/libjson.0.dylib $(PWD)/tmp/root/lib/libjson.0.dylib && \
	install_name_tool -id @executable_path/../lib/libjson.0.dylib $(PWD)/tmp/root/lib/libjson.dylib && \
	install_name_tool -change $(PWD)/tmp/root/lib/libjson-c.2.dylib @executable_path/../lib/libjson-c.2 $(PWD)/tmp/root/lib/libjson.0.dylib && \
	install_name_tool -change $(PWD)/tmp/root/lib/libjson-c.2.dylib @executable_path/../lib/libjson-c.2 $(PWD)/tmp/root/lib/libjson.dylib && \
	cp COPYING $(PWD)/tmp/root/licenses/json-c.txt && \
	cd .. && \
	cp ../libyubikey-$(LIBYUBIKEYVERSION).tar.gz . \
		|| 	wget http://yubico-c.googlecode.com/files/libyubikey-$(LIBYUBIKEYVERSION).tar.gz && \
	tar xfz libyubikey-$(LIBYUBIKEYVERSION).tar.gz && \
	cd libyubikey-$(LIBYUBIKEYVERSION) && \
	./configure --prefix=$(PWD)/tmp/root && \
	make install $(CHECK) && \
	install_name_tool -id @executable_path/../lib/libyubikey.0.dylib $(PWD)/tmp/root/lib/libyubikey.dylib && \
	install_name_tool -id @executable_path/../lib/libyubikey.0.dylib $(PWD)/tmp/root/lib/libyubikey.0.dylib && \
	cp COPYING $(PWD)/tmp/root/licenses/libyubikey.txt && \
	cd .. && \
	cp ../ykpers-$(VERSION).tar.gz . \
		|| wget http://yubikey-personalization.googlecode.com/files/ykpers-$(VERSION).tar.gz && \
	tar xfz ykpers-$(VERSION).tar.gz && \
	cd ykpers-$(VERSION)/ && \
	PKG_CONFIG_PATH=$(PWD)/tmp/root/lib/pkgconfig ./configure --prefix=$(PWD)/tmp/root --with-libyubikey-prefix=$(PWD)/tmp/root && \
	make install $(CHECK) && \
	install_name_tool -id @executable_path/../lib/libykpers-1.1.dylib $(PWD)/tmp/root/lib/libykpers-1.dylib && \
	install_name_tool -id @executable_path/../lib/libykpers-1.1.dylib $(PWD)/tmp/root/lib/libykpers-1.1.dylib && \
	for executable in $(PWD)/tmp/root/bin/*; do \
	install_name_tool -change $(PWD)/tmp/root/lib/libyubikey.0.dylib @executable_path/../lib/libyubikey.0.dylib $$executable && \
	install_name_tool -change $(PWD)/tmp/root/lib/libykpers-1.1.dylib @executable_path/../lib/libykpers-1.1.dylib $$executable ; \
	done && \
	cp COPYING $(PWD)/tmp/root/licenses/yubikey-personalization.txt && \
	cd .. && \
	cd root && \
	zip -r ../../ykpers-$(VERSION)-mac.zip *

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
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION)-win$(BITS).zip.sig \
	 -l OpSys-Windows
	googlecode_upload.py \
	 -s "Windows $(BITS)-bit binaries of $(PACKAGE) $(VERSION)" \
	 -p $(PROJECT) -u $(USER) $(PACKAGE)-$(VERSION)-win$(BITS).zip \
	 -l OpSys-Windows,Type-Executable

upload-ykpers4win32:
	$(MAKE) -f ykpers4win.mk upload-ykpers4win BITS=32

upload-ykpers4win64:
	$(MAKE) -f ykpers4win.mk upload-ykpers4win BITS=64
