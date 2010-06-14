#!/bin/bash

# Copyright (c) 2010 David Dindorp <ddi@snex.dk>
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

for arg in $*; do
	if [ "$arg" == "--help" ]; then
		echo "Usage:"
		echo "	Insert Yubikeys while this program is running to enable programming mode."
		return 1 2>/dev/null
		exit 1
	fi
done

if [ `id -u` -ne 0 ]; then
	echo "ERROR: Use 'sudo' to run this program. It's a Unix thing.">&2
	return 1 2>/dev/null
	exit 1
fi

grep -q Yubico /sys/bus/usb/devices/*/product; if [ $? -eq 0 ]; then
	echo "Note: Replug existing keys to switch them from keyboard to programming mode."
fi

echo "Waiting for keys..."
tail -n0 -f /var/log/messages | grep --line-buffered Yubikey | while read line; do
	# Should probably use a simpler tool such as sed or awk, but alas,
	# for once Perl has won the least cryptic syntax competition.
	devid=`echo $line|perl -nle 'print $1 if /(\d+-\d+:\d+\.\d+)/'`
	if [ "$devid" == "" ]; then continue; fi
	echo "Key plugged in. Unbinding HID driver from device $devid."
	echo $devid > /sys/bus/usb/drivers/usbhid/unbind
done
