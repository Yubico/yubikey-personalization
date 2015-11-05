/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2012-2015 Yubico AB
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

#include <ykstatus.h>
#include <ykcore.h>
#include <ykdef.h>

struct versions {
	int major;
	int minor;
	int build;
	bool support;
} supported[] = {
	{0,8,0,false},
	{0,9,9,true},
	{1,2,9,true},
	{1,3,1,true},
	{1,4,5,false},
	{2,0,2,true},
	{2,1,1,true},
	{2,2,3,true},
	{2,3,0,true},
	{2,4,5,true},
	{2,5,2,true},
	{2,6,0,false},
	{3,0,1,true},
	{3,2,8,true},
	{3,3,0,true},
	{3,4,3,true},
	{3,5,1,false},
	{4,0,1,true},
	{4,1,2,true},
	{4,1,10,true},
	{4,2,1,true},
	{4,3,7,true},
	{4,4,5,false},
	{5,0,0,false},
};

static YK_STATUS * _test_init_st(int major, int minor, int build)
{
	YK_STATUS *st = ykds_alloc();
	struct status_st *t;

	t = (struct status_st *) st;

	/* connected key details */
	t->versionMajor = major;
	t->versionMinor = minor;
	t->versionBuild = build;

	return st;
}

static void _test_yk_firmware(void)
{
	size_t i;
	for(i = 0; i < sizeof(supported) / sizeof(struct versions); i++) {
		int rc;
		YK_STATUS *st = _test_init_st(supported[i].major, supported[i].minor, supported[i].build);
		printf("testing: %d.%d.%d\n", supported[i].major, supported[i].minor, supported[i].build);
		rc = yk_check_firmware_version2(st);
		if(supported[i].support == true) {
			assert(rc == 1);
		} else {
			assert(yk_errno == YK_EFIRMWARE);
			assert(rc == 0);
		}
		ykds_free(st);
	}
}

int main(void)
{
	_test_yk_firmware();

	return 0;
}

