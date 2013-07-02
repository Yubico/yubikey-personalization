#!/bin/sh

# Copyright (c) 2012-2013 Yubico AB.  All rights reserved.
# Author: Simon Josefsson <simon@josefsson.org>.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following
#   disclaimer in the documentation and/or other materials provided
#   with the distribution.
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

OLDCSVFILE="$1"
NEWCSVFILE="$2"

if test -z "$OLDCSVFILE" || test -z "$NEWCSVFILE"; then
    echo "Usage: $0 OLDCSVFILE NEWCSVFILE"
    echo ""
    echo "This tool re-program YubiKeys in 6-digit OATH mode, unlocking an"
    echo "earlier configuration.  The old configuration (serial number and"
    echo "unlock code) is read from OLDCSVFILE and new data is appended to"
    echo "the NEWCSVFILE.  The NEWCSVFILE is also used to double check that"
    echo "the same YubiKey is not reprogrammed twice."
    echo ""
    echo "The input file is a comma-separated value (CSV) file following"
    echo "this format:"
    echo ""
    echo "SERIALNO,,COUNTER,HEXSECRET,UNLOCKCODE,TIME"
    echo ""
    echo "As illustration, consider the following three lines:"
    echo ""
    echo "1458800,,11344,dee628e652b08415c7f36d91b74a9d2a0b1251cf,08caa18ad869,2012-07-31T09:19:07,"
    echo "1458801,,106976,f7df4ddc61b585613975d0efac4505664730f0f9,7ddb2662e32c,2012-07-31T09:19:07,"
    echo "1458802,,627328,4d668d01c7e2fa336384e6d8b8839bbb00be10bf,b440a34cd994,2012-07-31T09:19:07,"
    echo ""
    echo "This tool is intended as a basis for your own modifications, thus"
    echo "you probably want to read the source code before using it."
    exit 1
fi

when=`date +%Y-%m-%dT%H:%M:%S`

while sleep 1; do
    # Read serial number.
    serialno=`ykinfo -s -q 2> /dev/null`
    rc=$?
    if test "$rc" != "0"; then
	# ykinfo already printed an error message
	continue
    fi

    hits=`grep "^$serialno," $OLDCSVFILE | wc -l`
    if test "$hits" != "1"; then
	echo "No unique entry for serial $serialno in file (found $hits matches)..."
	continue
    fi

    if test -f $NEWCSVFILE && grep -q "^$serialno," $NEWCSVFILE; then
	echo "YubiKey $serialno already re-programmed?!  Empty NEWCSVFILE if certain..."
	continue
    fi

    old_unlock=`grep "^$serialno," $OLDCSVFILE | cut -d, -f5`

    echo "notice: Found YubiKey serial $serialno with old unlock code $oldunlock..."

    secret=`dd if=/dev/urandom bs=20 count=1 2>/dev/null | hexdump -v -e '/1 "%02x"'`
    new_unlock=`dd if=/dev/urandom bs=6 count=1 2>/dev/null | hexdump -v -e '/1 "%02x"'`
    seed=`dd if=/dev/urandom bs=2 count=1 2>/dev/null | hexdump -v -e '/2 "%u"'`
    seed=`expr "$seed" "*" 16`

    echo "notice: Using secret $secret unlock code $new_unlock and seed $seed..."

    ykpersonalize -1 -a$secret -c$old_unlock -ooath-hotp -oappend-cr -oaccess=$new_unlock -ooath-imf=$seed -oprotect-cfg2 -oserial-api-visible -y

    echo "$serialno,,$seed,$secret,$new_unlock,$when," >> $NEWCSVFILE

    echo "Finished!  Remove YubiKey..."
done
