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
		fprintf(stderr, "0x%02x", *p);
		if (i < (size - 1))
			fprintf(stderr, ", ");

		if (! ((i + 1) % break_on))
			fprintf(stderr, "\n");
		p++;
	}
	fprintf(stderr, "\n");
	fflush(stderr);
}

void _check_success(int rc, YKP_CONFIG *cfg, unsigned char expected[], int caller_line)
{
	struct config_st *ycfg;
	bool config_matches_expected = false;

	if (rc != 1) {
		fprintf(stderr, "TEST FAILED (line %i of %s)\n", caller_line, __FILE__);
		fprintf(stderr, "Error returned : %i/%i (%s)\n", rc, ykp_errno, ykp_strerror(ykp_errno));
	}
	assert(rc == 1);

	ycfg = (struct config_st *) ykp_core_config(cfg);
	/* insert CRC */
	ycfg->crc = ~yubikey_crc16 ((unsigned char *) ycfg,
				    offsetof(struct config_st, crc));

	config_matches_expected = ! memcmp(expected, ycfg, sizeof(*ycfg));
	if (! config_matches_expected) {
		fprintf(stderr, "TEST FAILED (line %i of %s)\n", caller_line, __FILE__);
		_yktest_hexdump ("BAD MATCH :\n", ycfg, sizeof(*ycfg), 7);
		_yktest_hexdump ("EXPECTED :\n", expected, sizeof(*ycfg), 7);
	}
	assert(config_matches_expected == true);
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

/*
 * Utility function to parse arguments and just return the result code.
 * The calling function does the assert() to get function name in assert output.
 */
int _parse_args_rc(char **argv)

{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	int argc = sizeof *argv/sizeof *argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);

	ykp_free_config(cfg);
	free(st);

	return rc;
}

int _test_config_slot1()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(1, 3, 0);
	int rc = 0;
	struct config_st *ycfg;

	unsigned char expected[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
		0x00, 0x46, 0xc0
	};

	char *argv[] = {
		"unittest", "-1",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	_check_success(rc, cfg, expected, __LINE__);

	ykp_free_config(cfg);
	free(st);
}

int _test_config_static_slot2()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 0, 0);
	int rc = 0;
	struct config_st *ycfg;

	unsigned char expected[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
		0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
		0x3d, 0x3e, 0x3f, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x20, 0xf0, 0x00,
		0x00, 0xe9, 0xf5
	};

	char *argv[] = {
		"unittest", "-2", "-a303132333435363738393a3b3c3d3e3f",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	_check_success(rc, cfg, expected, __LINE__);

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

	unsigned char expected[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x00,
		0x00, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
		0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
		0x3d, 0x3e, 0x3f, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
		0x00, 0x6a, 0xb9
	};

	char *argv[] = {
		"unittest", "-1", "-a303132333435363738393a3b3c3d3e3f40414243", "-ooath-hotp", "-o-append-cr",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	_check_success(rc, cfg, expected, __LINE__);

	ykp_free_config(cfg);
	free(st);
}

int _test_extended_flags1()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	/* this matches the python-yubico test case test_challenge_response_hmac_nist */
	unsigned char expected[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x00,
		0x00, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
		0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
		0x3d, 0x3e, 0x3f, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x04, 0x40, 0x26, 0x00,
		0x00, 0x98, 0x41, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x03, 0x95, 0x56, 0x00, 0x00, 0x00,
	};

	char *argv[] = {
		"unittest", "-2", "-a303132333435363738393a3b3c3d3e3f40414243",
		"-ochal-resp", "-ochal-hmac", "-ohmac-lt64", "-oserial-api-visible",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	_check_success(rc, cfg, expected, __LINE__);

	ykp_free_config(cfg);
	free(st);
}

int _test_two_slots1()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	/* Test that it is not possible to choose slot more than once */
	char *argv[] = {
		"unittest", "-1", "-1",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);

	ykp_free_config(cfg);
	free(st);
}

int _test_two_slots2()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	/* Test that it is not possible to choose slot more than once */
	char *argv[] = {
		"unittest", "-2", "-1",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);

	ykp_free_config(cfg);
	free(st);
}

int _test_two_modes_at_once1()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	/* Test that it is not possible to choose mode (OATH-HOTP/CHAL-RESP) more than once */
	char *argv[] = {
		"unittest", "-ochal-resp", "-ooath-hotp",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);

	ykp_free_config(cfg);
	free(st);
}

int _test_two_modes_at_once2()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	/* Test that it is not possible to choose mode (OATH-HOTP/CHAL-RESP) more than once */
	char *argv[] = {
		"unittest", "-ochal-resp", "-ochal-resp",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);

	ykp_free_config(cfg);
	free(st);
}

int _test_mode_after_other_option()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	/* Test that it is not possible to set mode after other options */
	char *argv[] = {
		"unittest", "-ohmac-lt64", "-ochal-resp",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);

	ykp_free_config(cfg);
	free(st);
}

int _test_key_mixed_case1()
{
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	/* Make sure key with mixed case is rejected (parsing function yubikey_hex_decode
	 * only handles lower case hex)
	 */
	char *argv[] = {
		"unittest", "-1", "-a0000000000000000000000000000000E",
		NULL
	};
	int argc = sizeof argv/sizeof argv[0] - 1;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);

	ykp_free_config(cfg);
	free(st);
}

int _test_uid_for_oath()
{
	/* Test that it is not possible to specify UID with OATH */
	char *argv[] = {
		"unittest", "-ooath-hotp", "-ouid=h:010203040506",
		NULL
	};
	int rc = _parse_args_rc (argv);
	assert(rc == 0);
}

int _test_uid_for_chal_resp()
{
	/* Test that it is not possible to specify UID with Challenge Response */
	char *argv[] = {
		"unittest", "-ochal-resp", "-ouid=h:010203040506",
		NULL
	};
	int rc = _parse_args_rc (argv);
	assert(rc == 0);
}

int main (int argc, char **argv)
{
	_test_config_slot1();
	_test_config_static_slot2();
	_test_too_old_key();
	_test_too_new_key();
	_test_non_config_args();
	_test_oath_hotp_nist_160_bits();
	_test_extended_flags1();
	_test_two_slots1();
	_test_two_slots2();
	_test_two_modes_at_once1();
	_test_two_modes_at_once2();
	_test_mode_after_other_option();
	_test_key_mixed_case1();
	_test_uid_for_oath();
	_test_uid_for_chal_resp();

	return 0;
}
