/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008-2012 Yubico AB
 * Copyright (c) 2009 Christer Kaivo-oja <christer.kaivooja@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ykcore.h"
#include "ykdef.h"
#include "ykcore_backend.h"

#include <IOKit/hid/IOHIDLib.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <CoreFoundation/CoreFoundation.h>

#include "ykcore_backend.h"

#define	FEATURE_RPT_SIZE		8

static IOHIDManagerRef ykosxManager = NULL;
static IOReturn _ykusb_IOReturn = 0;

int _ykusb_start(void)
{
	ykosxManager = IOHIDManagerCreate( kCFAllocatorDefault, 0L );

	return 1;
}

int _ykusb_stop(void)
{
	if (ykosxManager != NULL) {
		CFRelease(ykosxManager);
		ykosxManager = NULL;
		return 1;
	}

	yk_errno = YK_EUSBERR;
	return 0;
}

static void _ykosx_CopyToCFArray(const void *value, void *context)
{
	CFArrayAppendValue( ( CFMutableArrayRef ) context, value );
}

void *_ykusb_open_device(int vendor_id, int product_id)
{
	void *yk = NULL;
	CFDictionaryRef dict;
	CFStringRef keys[2];
	CFStringRef values[2];

	int rc = YK_ENOKEY;

	CFNumberRef vendorID = CFNumberCreate( kCFAllocatorDefault, kCFNumberIntType, &vendor_id );
	CFNumberRef productID = CFNumberCreate( kCFAllocatorDefault, kCFNumberIntType, &product_id );

	keys[0] = CFSTR( kIOHIDVendorIDKey );  values[0] = (void *) vendorID;
	keys[1] = CFSTR( kIOHIDProductIDKey ); values[1] = (void *) productID;

	dict = CFDictionaryCreate( kCFAllocatorDefault, (const void **) &keys, (const void **) &values, 1, NULL, NULL);

	IOHIDManagerSetDeviceMatching( ykosxManager, dict );

	CFSetRef devSet = IOHIDManagerCopyDevices( ykosxManager );

	if ( devSet ) {
		rc = YK_EUSBERR;

		CFMutableArrayRef array = CFArrayCreateMutable( kCFAllocatorDefault, 0, NULL );

		CFSetApplyFunction( devSet, _ykosx_CopyToCFArray, array );

		CFIndex cnt = CFArrayGetCount( array );

		if (cnt > 0) {
			yk = (void *) CFArrayGetValueAtIndex( array, 0 );
			CFRetain(yk);
		}
		else {
			rc = YK_ENOKEY;
		}

		CFRelease( array );
		CFRelease( devSet );
	}

	CFRelease( dict );
	CFRelease( vendorID );
	CFRelease( productID );

	if (yk) {
		_ykusb_IOReturn = IOHIDDeviceOpen( yk, 0L );

		if ( _ykusb_IOReturn != kIOReturnSuccess ) {
			yk_release();
			goto error;
		}

		return yk;
	}

error:
	yk_errno = rc;
	return 0;
}

int _ykusb_close_device(void *dev)
{
	_ykusb_IOReturn = IOHIDDeviceClose( dev, 0L );
	CFRelease(dev);

	if ( _ykusb_IOReturn == kIOReturnSuccess )
		return 1;

	yk_errno = YK_EUSBERR;
	return 0;
}

int _ykusb_read(void *dev, int report_type, int report_number,
		char *buffer, int size)
{
	CFIndex sizecf = (CFIndex)size;

	if (report_type != REPORT_TYPE_FEATURE)
	{
		yk_errno = YK_ENOTYETIMPL;
		return 0;
	}

	_ykusb_IOReturn = IOHIDDeviceGetReport( dev, kIOHIDReportTypeFeature, report_number, (uint8_t *)buffer, (CFIndex *) &sizecf );

	if ( _ykusb_IOReturn != kIOReturnSuccess )
	{
		yk_errno = YK_EUSBERR;
		return 0;
	}

	return (int)sizecf;
}

int _ykusb_write(void *dev, int report_type, int report_number,
		char *buffer, int size)
{
	if (report_type != REPORT_TYPE_FEATURE)
	{
		yk_errno = YK_ENOTYETIMPL;
		return 0;
	}

	_ykusb_IOReturn = IOHIDDeviceSetReport( dev, kIOHIDReportTypeFeature, report_number, (unsigned char *)buffer, size);

	if ( _ykusb_IOReturn != kIOReturnSuccess )
	{
		yk_errno = YK_EUSBERR;
		return 0;
	}

	return 1;
}

const char *_ykusb_strerror()
{
	return "USB error\n";
//	fprintf(out, "USB error: %x\n", _ykusb_IOReturn);
}
