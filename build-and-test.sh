#!/bin/sh

set -x

if [ "x$TRAVIS_OS_NAME" != "xosx" ]; then
    sudo apt-get update -qq || true
    sudo apt-get remove -qq -y $REMOVE
    sudo apt-get autoremove -qq
    sudo apt-get install -qq -y --no-install-recommends libyubikey-dev asciidoc docbook-xsl xsltproc libxml2-utils $EXTRA
else
    brew update
    brew uninstall libtool
    brew install libtool
    brew install libyubikey
    brew install json-c
    brew install asciidoc
    brew install docbook-xsl
    # this is required so asciidoc can find the xml catalog
    export XML_CATALOG_FILES=/usr/local/etc/xml/catalog
fi

set -e

autoreconf -ifv

if [ "x$LIBUSB" = "xwindows" ]; then
    ./configure --with-backend=stub
    touch ChangeLog
    make dist

    if [ "x$ARCH" = "x32" ]; then
        export CC=i686-w64-mingw32-gcc
    else
        export CC=x86_64-w64-mingw32-gcc
    fi
    make -f ykpers4win.mk ykpers4win${ARCH} `grep ^VERSION Makefile|sed 's/ = /=/'`
else
    ./configure --with-backend=$LIBUSB $COVERAGE
    make check-doc-dist
    make check
    if [ "x$COVERAGE" != "x" ]; then
        gem install coveralls-lcov
        coveralls-lcov coverage/app2.info
    fi
fi
