/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008-2014 Yubico AB
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

#error "To be implemented!"

#include "ykcore.h"
#include "ykdef.h"
#include "ykcore_backend.h"

int _ykusb_start(void)
{
	yk_errno = YK_ENOTYETIMPL;
	return 0;
}

int _ykusb_stop(void)
{
	yk_errno = YK_ENOTYETIMPL;
	return 0;
}

void * _ykusb_open_device(int vendor_id, int *product_ids, size_t pids_len)
{
	yk_errno = YK_ENOTYETIMPL;
	return NULL;
}

int _ykusb_close_device(void *yk)
{
	yk_errno = YK_ENOTYETIMPL;
	return 0;
}

int _ykusb_read(void *dev, int report_type, int report_number,
		char *buffer, int buffer_size)
{
	yk_errno = YK_ENOTYETIMPL;
	return 0;
}

int _ykusb_write(void *dev, int report_type, int report_number,
		 char *buffer, int buffer_size)
{
	yk_errno = YK_ENOTYETIMPL;
	return 0;
}

int _ykusb_get_vid_pid(void *dev, int *vid, int *pid)
{
	yk_errno = YK_ENOTYETIMPL;
	return 0;
}

const char *_ykusb_strerror(void)
{
	yk_errno = YK_ENOTYETIMPL;
	return 0;
}
