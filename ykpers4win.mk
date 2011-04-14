LIBYUBIKEYVERSION=1.7
PROJECT=yubikey-personalization
PACKAGE=ykpers
VERSION=1.5.2
USER=simon@yubico.com
KEYID=2117364A

all: hack-wine ykpers4win32 ykpers4win64

DLLS=$(HOME)/.wine/drive_c/windows/system32
.PHONY: hack-wine
hack-wine:
	test -L $(DLLS)/libyubikey-0.dll || \
		ln -sv $(PWD)/tmp/root/bin/libyubikey-0.dll $(DLLS)/

ykpers4win:
	rm -rf tmp && mkdir tmp && cd tmp && \
	wget http://yubico-c.googlecode.com/files/libyubikey-$(LIBYUBIKEYVERSION).tar.gz && \
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
	$(MAKE) -f ykpers4win.mk ykpers4win ARCH=64 HOST=x86_64-w64-mingw32 CHECK=

upload-ykpers4win:
	gpg --detach-sign --default-key $(KEYID) \
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
