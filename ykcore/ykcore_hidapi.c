/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2014 Yubico AB
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

#include <hidapi.h>
#include <stdio.h>
#include <string.h>

#include "ykcore.h"
#include "ykdef.h"
#include "ykcore_backend.h"

static int hidapi_inited = 0;
static int ykl_errno;

struct _ykusb_info {
	struct hid_device_info device_info;
	hid_device *device;
};

int _ykusb_start(void)
{
	if(hidapi_inited == 0) {
		ykl_errno = hid_init();
		if(ykl_errno) {
			yk_errno = YK_EUSBERR;
			return 0;
		}
		hidapi_inited = 1;
	}
	return 1;
}

int _ykusb_stop(void)
{
	if(hidapi_inited == 1) {
		ykl_errno = hid_exit();
		if(ykl_errno) {
			yk_errno = YK_EUSBERR;
			return 0;
		}
		hidapi_inited = 0;
		return 1;
	}
	yk_errno = YK_EUSBERR;
	return 0;
}

void * _ykusb_open_device(int vendor_id, int *product_ids, size_t pids_len)
{
	struct hid_device_info *di, *cur_dev, *dev = NULL;
	hid_device *h = NULL;
	int rc = YK_ENOKEY;
	struct _ykusb_info *yk = NULL;

	di = hid_enumerate (0, 0);

	for(cur_dev = di; cur_dev; cur_dev = cur_dev->next) {
		/* something of a hack to hard-code interface number 0, but OTP interface
		 * is always 0. */
		if(cur_dev->vendor_id == vendor_id && cur_dev->interface_number == 0) {
			size_t j;
			for(j = 0; j < pids_len; j++) {
				if (cur_dev->product_id == product_ids[j]) {
					if(dev == NULL) {
						dev = cur_dev;
					} else {
						rc = YK_EMORETHANONE;
						goto done;
					}
				}
			}
		}
	}

	if(dev != NULL) {
		h = hid_open_path(dev->path);
		if(h != NULL) {
			yk = malloc(sizeof(struct _ykusb_info));
			memcpy(&yk->device_info, dev, sizeof(struct hid_device_info));
			yk->device = h;
		}
	}

done:
	hid_free_enumeration(di);
	if(yk == NULL) {
		yk_errno = rc;
	}
	return yk;
}

int _ykusb_close_device(void *yk)
{
	struct _ykusb_info *dev = yk;
	hid_close(dev->device);
	free(dev);
	return 1;
}

int _ykusb_read(void *dev, int report_type, int report_number,
		char *buffer, int buffer_size)
{
	struct _ykusb_info *yk = dev;
	int len;
	unsigned char buf[buffer_size + 1];

	buf[0] = report_type << 8 | report_number;
	len = hid_get_feature_report(yk->device, buf, buffer_size + 1);
	if(len == -1) {
		yk_errno = YK_EUSBERR;
		return 0;
	}
	memcpy(buffer, buf + 1, buffer_size);
	return len;
}

int _ykusb_write(void *dev, int report_type, int report_number,
		 char *buffer, int buffer_size)
{
	struct _ykusb_info *yk = dev;
	unsigned char buf[buffer_size + 1];
	int len;

	buf[0] = report_type << 8 | report_number;
	memcpy(buf + 1, buffer, buffer_size);
	len = hid_send_feature_report(yk->device, buf, buffer_size + 1);
	if(len > 0) {
		return 1;
	}
	yk_errno = YK_EUSBERR;
	return 0;
}

int _ykusb_get_vid_pid(void *dev, int *vid, int *pid)
{
	struct _ykusb_info *yk = dev;
	*vid = yk->device_info.vendor_id;
	*pid = yk->device_info.product_id;
	return 1;
}

const char *_ykusb_strerror(void)
{
	yk_errno = YK_ENOTYETIMPL;
	return 0;
}
