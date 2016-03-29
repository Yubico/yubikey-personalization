/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008-2014 Yubico AB
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

static int _ykosx_getIntProperty( IOHIDDeviceRef dev, CFStringRef key ) {
	int result = 0;
	CFTypeRef tCFTypeRef = IOHIDDeviceGetProperty( dev, key );
	if ( tCFTypeRef ) {
		if ( CFNumberGetTypeID( ) == CFGetTypeID( tCFTypeRef ) ) {
			CFNumberGetValue( ( CFNumberRef ) tCFTypeRef, kCFNumberSInt32Type, &result );
		}
	}
	return result;
}

void *_ykusb_open_device(int vendor_id, int *product_ids, size_t pids_len, int index)
{
	void *yk = NULL;

	int rc = YK_ENOKEY;

	size_t i;
	int found = 0;

	IOHIDManagerSetDeviceMatchingMultiple( ykosxManager, NULL );

	CFSetRef devSet = IOHIDManagerCopyDevices( ykosxManager );

	if ( devSet ) {
		CFMutableArrayRef array = CFArrayCreateMutable( kCFAllocatorDefault, 0, NULL );

		CFSetApplyFunction( devSet, _ykosx_CopyToCFArray, array );

		CFIndex cnt = CFArrayGetCount( array );

		CFIndex i;

		for(i = 0; i < cnt; i++) {
			IOHIDDeviceRef dev = (IOHIDDeviceRef)CFArrayGetValueAtIndex( array, i );
			long usagePage = _ykosx_getIntProperty( dev, CFSTR( kIOHIDPrimaryUsagePageKey ));
			long usage = _ykosx_getIntProperty( dev, CFSTR( kIOHIDPrimaryUsageKey ));
			long devVendorId = _ykosx_getIntProperty( dev, CFSTR( kIOHIDVendorIDKey ));
			/* usagePage 1 is generic desktop and usage 6 is keyboard */
			if(usagePage == 1 && usage == 6 && devVendorId == vendor_id) {
				long devProductId = _ykosx_getIntProperty( dev, CFSTR( kIOHIDProductIDKey ));
				size_t j;
				for(j = 0; j < pids_len; j++) {
					if(product_ids[j] == devProductId) {
						found++;
						if(found-1 == index) {
							yk = dev;
							break;
						}
					}
				}
			}
		}

		/* this is a workaround for a memory leak in IOHIDManagerCopyDevices() in 10.8 */
		IOHIDManagerScheduleWithRunLoop( ykosxManager, CFRunLoopGetCurrent( ), kCFRunLoopDefaultMode );
		IOHIDManagerUnscheduleFromRunLoop( ykosxManager, CFRunLoopGetCurrent( ), kCFRunLoopDefaultMode );

		CFRelease( array );
		CFRelease( devSet );
	}

	if (yk) {
		CFRetain(yk);
		_ykusb_IOReturn = IOHIDDeviceOpen( yk, 0L );

		if ( _ykusb_IOReturn != kIOReturnSuccess ) {
			CFRelease(yk);
			rc = YK_EUSBERR;
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

	if(sizecf == 0)
		yk_errno = YK_ENODATA;

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

int _ykusb_get_vid_pid(void *yk, int *vid, int *pid) {
	IOHIDDeviceRef dev = (IOHIDDeviceRef)yk;
	*vid = _ykosx_getIntProperty( dev, CFSTR( kIOHIDVendorIDKey ));
	*pid = _ykosx_getIntProperty( dev, CFSTR( kIOHIDProductIDKey ));
	return 1;
}

const char *_ykusb_strerror()
{
	switch (_ykusb_IOReturn) {
		case kIOReturnSuccess:
			return "kIOReturnSuccess";
		case kIOReturnNotOpen:
			return "kIOReturnNotOpen";
		case kIOReturnNoDevice:
			return "kIOReturnNoDevice";
		case kIOReturnExclusiveAccess:
			return "kIOReturnExclusiveAccess";
		case kIOReturnError:
			return "kIOReturnError";
		case kIOReturnBadArgument:
			return "kIOReturnBadArgument";
		case kIOReturnAborted:
			return "kIOReturnAborted";
		case kIOReturnNotResponding:
			return "kIOReturnNotResponding";
		case kIOReturnOverrun:
			return "kIOReturnOverrun";
		case kIOReturnCannotWire:
			return "kIOReturnCannotWire";
		default:
			return "unknown error";
	}
}
