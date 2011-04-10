LIBYUBIKEYVERSION=1.7
YKPERSVERSION=1.5.1

all: ykpers4win32 ykpers4win64

ykpers4win:
	rm -rf tmp && mkdir tmp && cd tmp && \
	wget http://yubico-c.googlecode.com/files/libyubikey-$(LIBYUBIKEYVERSION).tar.gz && \
	tar xfa libyubikey-$(LIBYUBIKEYVERSION).tar.gz && \
	cd libyubikey-$(LIBYUBIKEYVERSION) && \
	./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root && \
	make install $(CHECK) && \
	cd .. && \
	cp ../ykpers-$(YKPERSVERSION).tar.gz . \
		|| wget http://yubikey-personalization.googlecode.com/files/ykpers-$(YKPERSVERSION).tar.gz && \
	tar xfa ykpers-$(YKPERSVERSION).tar.gz && \
	cd ykpers-$(YKPERSVERSION)/ && \
	./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root LDFLAGS=-L$(PWD)/tmp/root/lib CPPFLAGS=-I$(PWD)/tmp/root/include && \
	make install $(CHECK) && \
	cd .. && \
	cd root && \
	zip -r ../../ykpers-$(YKPERSVERSION)-win$(ARCH).zip *

ykpers4win32:
	$(MAKE) -f ykpers4win.mk ykpers4win ARCH=32 HOST=i686-w64-mingw32 CHECK=

ykpers4win64:
	$(MAKE) -f ykpers4win.mk ykpers4win ARCH=64 HOST=x86_64-w64-mingw32 CHECK=
