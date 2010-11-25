ykpers4win32:
	rm -rf tmp && mkdir tmp && cd tmp && \
	wget -q http://yubico-c.googlecode.com/files/libyubikey-1.7.tar.gz && \
	tar xfa libyubikey-1.7.tar.gz && \
	cd libyubikey-1.7 && \
	./configure --host=i686-w64-mingw32 --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root && \
	make install check && \
	cd .. && \
	wget -q http://yubikey-personalization.googlecode.com/files/libusb-1.0.8-windows.tar.bz2 && \
	tar xfa libusb-1.0.8-windows.tar.bz2 && \
	cd libusb-1.0.8 && \
	./configure --host=i686-w64-mingw32 --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root && \
	make install && \
	cd .. && \
	wget -q http://yubikey-personalization.googlecode.com/files/ykpers-1.3.5.tar.gz && \
	tar xfa ykpers-1.3.5.tar.gz && \
	cd ykpers-1.3.5/ && \
	PKG_CONFIG_PATH=$(PWD)/tmp/root/lib/pkgconfig ./configure --host=i686-w64-mingw32 --build=x86_64-unknown-linux-gnu --prefix=$(PWD)/tmp/root && \
	make install check && \
	cd .. && \
	cd root && \
	zip -r ../../ykpers-1.3.5-win32.zip *
