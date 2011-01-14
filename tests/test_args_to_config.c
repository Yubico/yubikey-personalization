/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2011, Yubico AB
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

#include <unistd.h>
#include <stdlib.h>

#include <ykpers.h>
#include <ykdef.h>
/*
#include <ykcore.h>
#include <ykcore_lcl.h>
*/

/* duplicated from ykpers.c */
struct ykp_config_t {
	unsigned int yk_major_version;
	unsigned int yk_minor_version;
	unsigned int configuration_number;

	struct config_st *ykcore_config;
};

void _yktest_hexdump(char *prefix, void *buffer, int size, int break_on)
{
	unsigned char *p = buffer;
	int i;
	if (prefix != NULL)
		fprintf(stderr, "%s", prefix);
	for (i = 0; i < size; i++) {
		fprintf(stderr, " %02x", *p);
		if (! ((i + 1) % break_on))
			fprintf(stderr, "\n");
		p++;
	}
	fprintf(stderr, "\n");
	fflush(stderr);
}

int _test_config (YKP_CONFIG *cfg, YK_STATUS *st, int argc, char **argv)
{
	const char *infname = NULL;
	const char *outfname = NULL;
	bool verbose = false;
	bool aesviahash = false;
	bool use_access_code = false;
	unsigned char access_code[256];
	YK_KEY *yk = 0;
	bool autocommit = false;
	int exit_code = 0;

	/* Options */
	char *salt = NULL;

	int rc;

	ykp_errno = 0;
	optind = 0; /* getopt reinit */

	/* copy version number from st into cfg */
	assert(ykp_configure_for(cfg, 1, st) == 1);

	/* call args_to_config from ykpersonalize.c with a fake set of program arguments */
	rc = args_to_config(argc, argv, cfg,
			    &infname, &outfname,
			    &autocommit, salt,
			    st, &verbose,
			    access_code, &use_access_code,
			    &aesviahash,
			    &exit_code);

	return rc;
}

YK_STATUS * _test_init_st(int major, int minor, int build)
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

int _test_config_slot1()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(1, 3, 0);
	int rc = 0;
	struct config_st *ycfg;
	
	char *argv[] = {
		"unittest", "-1",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 1);

	/* verify required version for this config */
	assert(cfg->yk_major_version == 1);
	assert(cfg->yk_minor_version == 3);

	/* verify some specific flags */
	ycfg = (struct config_st *) ykp_core_config(cfg);
	assert(ycfg->tktFlags == TKTFLAG_APPEND_CR);

	/* then check CRC against a known value to bulk check the rest */
	ycfg->crc = ~yubikey_crc16 ((unsigned char *) ycfg,
				    offsetof(struct config_st, crc));

	if (ycfg->crc != 0xc046)
		_yktest_hexdump ("NO-MATCH :\n", ycfg, sizeof(*ycfg), 8);

	assert(ycfg->crc == 0xc046);

	ykp_free_config(cfg);
	free(st);
}

int _test_config_static_slot2()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 0, 0);
	int rc = 0;
	struct config_st *ycfg;

	char *argv[] = {
		"unittest", "-2", "-a303132333435363738393a3b3c3d3e3f",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 1);

	/* verify required version for this config */
	assert(cfg->yk_major_version == 2);
	assert(cfg->yk_minor_version == 0);

	/* verify some specific flags */
	ycfg = (struct config_st *) ykp_core_config(cfg);
	assert(ycfg->tktFlags == TKTFLAG_APPEND_CR);
	assert(ycfg->cfgFlags == CFGFLAG_STATIC_TICKET | CFGFLAG_STRONG_PW1 | CFGFLAG_STRONG_PW2 | CFGFLAG_MAN_UPDATE);

	/* then check CRC against a known value to bulk check the rest */
	ycfg->crc = ~yubikey_crc16 ((unsigned char *) ycfg,
				    offsetof(struct config_st, crc));

	if (ycfg->crc != 0xf5e9)
		_yktest_hexdump ("NO-MATCH :\n", ycfg, sizeof(*ycfg), 8);

	assert(ycfg->crc == 0xf5e9);

	ykp_free_config(cfg);
	free(st);
}

int _test_too_old_key()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(1, 3, 0);
	int rc = 0;

	char *argv[] = {
		"unittest", "-oshort-ticket",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);
	assert(ykp_errno == YKP_EYUBIKEYVER);

	ykp_free_config(cfg);
	free(st);
}

int _test_too_new_key()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	char *argv[] = {
		"unittest", "-oticket-first",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);
	assert(ykp_errno == YKP_EYUBIKEYVER);

	ykp_free_config(cfg);
	free(st);
}

int _test_non_config_args()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	const char *infname = NULL;
	const char *outfname = NULL;
	bool verbose = false;
	bool aesviahash = false;
	bool use_access_code = false;
	unsigned char access_code[256];
	YK_KEY *yk = 0;
	bool autocommit = false;
	int exit_code = 0;
	int i;

	/* Options */
	char *salt = NULL;

	char *argv[] = {
		"unittest", "-sout", "-iin", "-c313233343536", "-y", "-v",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	ykp_errno = 0;
	optind = 0; /* getopt reinit */

	/* copy version number from st into cfg */
	assert(ykp_configure_for(cfg, 1, st) == 1);

	/* call args_to_config from ykpersonalize.c with a fake set of program arguments */
	rc = args_to_config(argc, argv, cfg,
			    &infname, &outfname,
			    &autocommit, salt,
			    st, &verbose,
			    access_code, &use_access_code,
			    &aesviahash,
			    &exit_code);
	assert(rc == 1);
	i = strcmp(infname, "in"); assert(i == 0);
	i = strcmp(outfname, "out"); assert(i == 0);
	i = strcmp(access_code, "123456"); assert(i == 0);
	assert(autocommit == true);
	assert(verbose == true);

	ykp_free_config(cfg);
	free(st);
}

int _test_oath_hotp_nist_160_bits()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 1, 0);
	int rc = 0;
	struct config_st *ycfg;

	char *argv[] = {
		"unittest", "-1", "-a303132333435363738393a3b3c3d3e3f40414243", "-ooath-hotp", "-o-append-cr",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 1);

	/* verify required version for this config */
	assert(cfg->yk_major_version == 2);
	assert(cfg->yk_minor_version == 1);

	/* verify some specific flags */
	ycfg = (struct config_st *) ykp_core_config(cfg);
	assert(ycfg->tktFlags == TKTFLAG_OATH_HOTP);
	assert(ycfg->cfgFlags == 0);

	/* then check CRC against a known value to bulk check the rest */
	ycfg->crc = ~yubikey_crc16 ((unsigned char *) ycfg,
				    offsetof(struct config_st, crc));

	if (ycfg->crc != 0xb96a)
		_yktest_hexdump ("NO-MATCH :\n", ycfg, sizeof(*ycfg), 8);

	assert(ycfg->crc == 0xb96a);

	ykp_free_config(cfg);
	free(st);
}

int main (int argc, char **argv)
{
	_test_config_slot1();
	_test_config_static_slot2();
	_test_too_old_key();
	_test_too_new_key();
	_test_non_config_args();
	_test_oath_hotp_nist_160_bits();

	return 0;
}
