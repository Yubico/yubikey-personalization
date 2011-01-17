ykpers4win:
	rm -rf tmp && mkdir tmp && cd tmp && \
	wget http://yubico-c.googlecode.com/files/libyubikey-1.7.tar.gz && \
	tar xfa libyubikey-1.7.tar.gz && \
	cd libyubikey-1.7 && \
	./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root && \
	make install $(CHECK) && \
	cd .. && \
	wget http://yubikey-personalization.googlecode.com/files/libusb-1.0.8-windows.tar.bz2 && \
	tar xfa libusb-1.0.8-windows.tar.bz2 && \
	cd libusb-1.0.8 && \
	./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root && \
	make install && \
	cd .. && \
	wget http://yubikey-personalization.googlecode.com/files/ykpers-1.4.0.tar.gz && \
	tar xfa ykpers-1.4.0.tar.gz && \
	cd ykpers-1.4.0/ && \
	PKG_CONFIG_PATH=$(PWD)/tmp/root/lib/pkgconfig ./configure --host=$(HOST) --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root CPPFLAGS=-I$(PWD)/tmp/root/include && \
	make install $(CHECK) && \
	cd .. && \
	cd root && \
	zip -r ../../ykpers-1.4.0-win$(ARCH).zip *

ykpers4win32:
	$(MAKE) -f ykpers4win.mk ykpers4win ARCH=32 HOST=i686-w64-mingw32 CHECK=check

ykpers4win64:
	$(MAKE) -f ykpers4win.mk ykpers4win ARCH=64 HOST=x86_64-w64-mingw32 CHECK=
