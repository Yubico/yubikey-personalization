/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2012-2013 Yubico AB
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
#include <assert.h>
#include <string.h>

#include "ykpers_lcl.h"
#include <ykpers.h>
#include <ykdef.h>

static YK_STATUS *init_status(int major, int minor, int build) {
	YK_STATUS *st = ykds_alloc();
	struct status_st *t;

	t = (struct status_st *) st;

	/* connected key details */
	t->versionMajor = major;
	t->versionMinor = minor;
	t->versionBuild = build;

	return st;
}

static void _test_ykp_export_ycfg_empty(void) {
	YKP_CONFIG *cfg = ykp_alloc();
	char out[1024] = {0};
	int res = ykp_export_config(cfg, out, 1024, YKP_FORMAT_YCFG);
	assert(res > 0);
	ykp_free_config(cfg);
}

static void _test_ykp_import_ycfg_simple(void) {
	YK_STATUS *st = init_status(2,2,3);
	YKP_CONFIG *cfg = ykp_alloc();
	YK_CONFIG ycfg;
  int res;
	char data[1024] = "{ \"yubiProdConfig\": { \"mode\": \"oathHOTP\", \"options\": { \"fixedModhex\": false, \"oathDigits\": 6, \"fixedSeedvalue\": 0, \"randomSeed\": false, \"tabFirst\": false, \"tabBetween\": false, \"tabLast\": false, \"appendDelay1\": false, \"appendDelay2\": false, \"appendCR\": true, \"protectSecond\": false, \"sendRef\": false, \"ticketFirst\": false, \"pacing10MS\": false, \"pacing20MS\": false, \"allowHidtrig\": false, \"serialBtnVisible\": true, \"serialUsbVisible\": false, \"serialApiVisible\": true, \"useNumericKeypad\": false, \"fastTrig\": false, \"allowUpdate\": false, \"dormant\": false, \"ledInverted\": false } } }";
	ykp_configure_version(cfg, st);
	res = ykp_import_config(cfg, data, strlen(data), YKP_FORMAT_YCFG);
	assert(res == 1);

	ycfg = cfg->ykcore_config;
	assert((ycfg.tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP);
	assert((ycfg.tktFlags & TKTFLAG_APPEND_CR) == TKTFLAG_APPEND_CR);

	ykp_free_config(cfg);
	ykds_free(st);
}


int main(void)
{
	_test_ykp_export_ycfg_empty();
	_test_ykp_import_ycfg_simple();

	return 0;
}

