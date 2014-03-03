/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2011-2013 Yubico AB
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
#include <string.h>
#include <assert.h>

#include <ykpers.h>
#include <ykdef.h>

static void _test_128_bits_key(YKP_CONFIG *ykp, struct config_st *cfg)
{
	unsigned char empty[256];

	memset (empty, 0, sizeof(empty));
	memset (cfg, 0, sizeof(struct config_st));
	cfg->tktFlags = TKTFLAG_APPEND_CR;

	ykp_AES_key_from_passphrase(ykp, "test", "ABCDEF");

	/* make sure config.key now has non-zero bytes in it */
	assert(memcmp(cfg->key, empty, sizeof(cfg->key)) != 0);
	/* make sure config.uid is still zero for 128 bits config */
	assert(memcmp(cfg->uid, empty, sizeof(cfg->uid)) == 0);
}

static void _test_160_bits_key(YKP_CONFIG *ykp, struct config_st *cfg)
{
	unsigned char empty[256];

	memset (empty, 0, sizeof(empty));
	memset (cfg, 0, sizeof(struct config_st));
	cfg->tktFlags = TKTFLAG_APPEND_CR | TKTFLAG_OATH_HOTP;

	ykp_AES_key_from_passphrase(ykp, "test", "ABCDEF");

	/* make sure config.key now has non-zero bytes in it */
	assert(memcmp(cfg->key, empty, sizeof(cfg->key)) != 0);
	/* make sure config.uid is NOT zero for 160 bits config */
	assert(memcmp(cfg->uid, empty, sizeof(cfg->uid)) != 0);
}

int main (void)
{
	YKP_CONFIG *ykp;
	struct config_st *ycfg;
	int rc;

	ykp = ykp_alloc ();
	if (!ykp)
	{
		printf ("ykp_alloc returned NULL\n");
		return 1;
	}

	ycfg = (struct config_st *) ykp_core_config(ykp);

	_test_128_bits_key(ykp, ycfg);
	_test_160_bits_key(ykp, ycfg);

	rc = ykp_free_config(ykp);
	if (!rc)
	{
		printf ("ykp_free_config => %d\n", rc);
		return 1;
	}

	return 0;
}
