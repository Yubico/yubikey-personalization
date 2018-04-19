/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2011-2014 Yubico AB
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

#include <yubikey.h>
#include <ykpers.h>
#include <ykdef.h>
/*
#include <ykcore.h>
#include <ykcore_lcl.h>
*/
#include <ykpers-args.h>

/* duplicated from ykpers.c */
struct ykp_config_t {
	unsigned int yk_major_version;
	unsigned int yk_minor_version;
	unsigned int yk_build_version;
	unsigned int command;

	struct config_st *ykcore_config;
};

static void _yktest_hexdump(const char *prefix, const void *buffer, int size, int break_on)
{
	unsigned const char *p = buffer;
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

static void _check_success(int rc, YKP_CONFIG *cfg, unsigned char expected[], int caller_line)
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
	ycfg->crc = yk_endian_swap_16(ycfg->crc);

	config_matches_expected = ! memcmp(expected, ycfg, sizeof(*ycfg));
	if (! config_matches_expected) {
		fprintf(stderr, "TEST FAILED (line %i of %s)\n", caller_line, __FILE__);
		_yktest_hexdump ("BAD MATCH :\n", ycfg, sizeof(*ycfg), 7);
		_yktest_hexdump ("EXPECTED :\n", expected, sizeof(*ycfg), 7);
	}
	assert(config_matches_expected == true);
}

static int _test_config (YKP_CONFIG *cfg, YK_STATUS *st, int argc, char **argv)
{
	const char *infname = NULL;
	const char *outfname = NULL;
	bool verbose = false;
	bool dry_run = false;
	bool use_access_code = false;
	char *access_code = NULL;
	char *new_access_code = NULL;
	bool autocommit = false;
	int exit_code = 0;
	int data_format = YKP_FORMAT_LEGACY;

	/* Options */
	char oathid[128] = {0};
	char ndef[128];
	char ndef_type = 0;
	unsigned char usb_mode = 0;
	unsigned char cr_timeout = 0;
	unsigned short autoeject_timeout = 0;
	int num_modes_seen = 0;
	bool zap = false;

	unsigned char scan_map[sizeof(SCAN_MAP)];
	unsigned char device_info[128];
	size_t device_info_len = 0;

	int rc;

	ykp_errno = 0;

/* getopt reinit (BSD systems use optreset and a different optind value) */
#if defined(__GLIBC__) || defined(_WIN32)
	optind = 0;
#else
	optind = optreset = 1;
#endif

	/* copy version number from st into cfg */
	assert(ykp_configure_for(cfg, 1, st) == 1);

	/* call args_to_config from ykpers-args.c with a fake set of program arguments */
	rc = args_to_config(argc, argv, cfg, oathid,
			    &infname, &outfname,
			    &data_format, &autocommit,
			    st, &verbose, &dry_run,
			    &access_code, &new_access_code,
			    &ndef_type, ndef, &usb_mode, &zap,
			    scan_map, &cr_timeout, &autoeject_timeout, &num_modes_seen,
			    device_info, &device_info_len, &exit_code);

	free(access_code);
	free(new_access_code);
	return rc;
}

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

/*
 * Utility function to parse arguments and just return the result code.
 * The calling function does the assert() to get function name in assert output.
 */
static int _parse_args_rc(int argc, char *argv[])
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	rc = _test_config(cfg, st, argc, argv);

	ykp_free_config(cfg);
	free(st);

	return rc;
}

static void _test_config_slot1(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(1, 3, 0);
	int rc = 0;

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
		"unittest", "-1", "-a", "h:00000000000000000000000000000000",
		NULL
	};
	int argc = 4;

	rc = _test_config(cfg, st, argc, argv);
	_check_success(rc, cfg, expected, __LINE__);

	ykp_free_config(cfg);
	free(st);
}

static void _test_config_static_slot2(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(2, 0, 0);
	int rc = 0;

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
	int argc = 3;

	rc = _test_config(cfg, st, argc, argv);
	_check_success(rc, cfg, expected, __LINE__);

	ykp_free_config(cfg);
	free(st);
}

static void _test_too_old_key(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(1, 3, 0);
	int rc = 0;

	char *argv[] = {
		"unittest", "-oshort-ticket",
		NULL
	};
	int argc = 2;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);
	assert(ykp_errno == YKP_EYUBIKEYVER);

	ykp_free_config(cfg);
	free(st);
}

static void _test_too_new_key(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	char *argv[] = {
		"unittest", "-oticket-first",
		NULL
	};
	int argc = 2;

	rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);
	assert(ykp_errno == YKP_EYUBIKEYVER);

	ykp_free_config(cfg);
	free(st);
}

static void _test_non_config_args(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(2, 2, 0);
	int rc = 0;

	const char *infname = NULL;
	const char *outfname = NULL;
	bool verbose = false;
	bool dry_run = false;
	char *access_code = NULL;
	char *new_access_code = NULL;
	bool autocommit = false;
	int exit_code = 0;
	int i;
	int data_format = YKP_FORMAT_LEGACY;

	/* Options */
	char oathid[128] = {0};
	char ndef[128];
	char ndef_type = 0;
	unsigned char usb_mode = 0;
	unsigned char cr_timeout = 0;
	unsigned short autoeject_timeout = 0;
	int num_modes_seen = 0;
	bool zap = false;

	unsigned char scan_map[sizeof(SCAN_MAP)];
	unsigned char device_info[128];
	size_t device_info_len = 0;

	char *argv[] = {
		"unittest", "-1", "-sout", "-iin", "-c313233343536", "-y", "-v",
		NULL
	};
	int argc = 7;

	ykp_errno = 0;

/* getopt reinit (BSD systems use optreset and a different optind value) */
#if defined(__GLIBC__) || defined(_WIN32)
	optind = 0;
#else
	optind = optreset = 1;
#endif

	/* copy version number from st into cfg */
  ykp_configure_version(cfg, st);
	//assert(ykp_configure_for(cfg, 1, st) == 1);

	/* call args_to_config from ykpers-args.c with a fake set of program arguments */
	rc = args_to_config(argc, argv, cfg, oathid,
			    &infname, &outfname,
			    &data_format, &autocommit,
			    st, &verbose, &dry_run,
			    &access_code, &new_access_code,
			    &ndef_type, ndef, &usb_mode, &zap,
			    scan_map, &cr_timeout, &autoeject_timeout, &num_modes_seen,
			    device_info, &device_info_len, &exit_code);
	assert(rc == 1);
	i = strcmp(infname, "in"); assert(i == 0);
	i = strcmp(outfname, "out"); assert(i == 0);
	i = memcmp(access_code, "313233343536", 12); assert(i == 0);
	assert(autocommit == true);
	assert(verbose == true);

	ykp_free_config(cfg);
	free(st);
	free(access_code);
	free(new_access_code);
}

static void _test_oath_hotp_nist_160_bits(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(2, 1, 0);
	int rc = 0;

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
	int argc = 5;

	rc = _test_config(cfg, st, argc, argv);
	_check_success(rc, cfg, expected, __LINE__);

	ykp_free_config(cfg);
	free(st);
}

static void _test_extended_flags1(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
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
	int argc = 7;

	rc = _test_config(cfg, st, argc, argv);
	_check_success(rc, cfg, expected, __LINE__);

	ykp_free_config(cfg);
	free(st);
}

static void _test_two_slots1(void)
{
	/* Test that it is not possible to choose slot more than once */
	char *argv[] = {
		"unittest", "-1", "-1",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_two_slots2(void)
{
	/* Test that it is not possible to choose slot more than once */
	char *argv[] = {
		"unittest", "-2", "-1",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_two_modes_at_once1(void)
{
	/* Test that it is not possible to choose mode (OATH-HOTP/CHAL-RESP) more than once */
	char *argv[] = {
		"unittest", "-ochal-resp", "-ooath-hotp",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_two_modes_at_once2(void)
{
	/* Test that it is not possible to choose mode (OATH-HOTP/CHAL-RESP) more than once */
	char *argv[] = {
		"unittest", "-ochal-resp", "-ochal-resp",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_mode_after_other_option(void)
{
	/* Test that it is not possible to set mode after other options */
	char *argv[] = {
		"unittest", "-ohmac-lt64", "-ochal-resp",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_key_mixed_case1(void)
{
	/* Make sure key with mixed case is rejected (parsing function yubikey_hex_decode
	 * only handles lower case hex)
	 */
	char *argv[] = {
		"unittest", "-1", "-a0000000000000000000000000000000E",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_uid_for_oath(void)
{
	/* Test that it is not possible to specify UID with OATH */
	char *argv[] = {
		"unittest", "-ooath-hotp", "-ouid=h:010203040506",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_uid_for_chal_resp(void)
{
	/* Test that it is not possible to specify UID with Challenge Response */
	char *argv[] = {
		"unittest", "-ochal-resp", "-ouid=h:010203040506",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_swap_with_slot(void)
{
	/* Test that you can not both swap and set slot */
	char *argv[] = {
		"unittest", "-x", "-1",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_slot_with_update(void)
{
	/* Test the update must be before slot */
	char *argv[] = {
		"unittest", "-1", "-u",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_swap_with_update(void)
{
	/* Test the update must be before slot */
	char *argv[] = {
		"unittest", "-u", "-x",
		NULL
	};
	int rc = _parse_args_rc (3, argv);
	assert(rc == 0);
}

static void _test_ndef_for_neo_beta(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(2, 1, 7);

	char *argv[] = {
		"unittest", "-nhttps://my.yubico.com/neo/",
		NULL
	};
	int argc = 2;

	int rc = _test_config(cfg, st, argc, argv);
	assert(rc == 1);
	assert(((struct ykp_config_t*)cfg)->command == SLOT_NDEF);

	ykp_free_config(cfg);
	free(st);
}

static void _test_ndef_with_non_neo(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(2, 2, 4);

	char *argv[] = {
		"unittest", "-nhttps://my.yubico.com/neo/",
		NULL
	};
	int argc = 2;

	int rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);

	ykp_free_config(cfg);
	free(st);
}

static void _test_slot_two_with_neo_beta(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(2, 1, 7);

	char *argv[] = {
		"unittest", "-2", NULL
	};
	int argc = 2;

	int rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);
	ykp_free_config(cfg);
	free(st);
}

static void _test_ndef2_with_neo_beta(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(2, 1, 7);

	char *argv[] = {
		"unittest", "-2", "-nhttps://my.yubico.com/neo/",
		NULL
	};
	int argc = 3;

	int rc = _test_config(cfg, st, argc, argv);
	assert(rc == 0);
	ykp_free_config(cfg);
	free(st);
}

static void _test_ndef2_with_neo(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(3, 0, 0);

	char *argv[] = {
		"unittest", "-2", "-nhttps://my.yubico.com/neo/",
		NULL
	};
	int argc = 3;

	int rc = _test_config(cfg, st, argc, argv);
	assert(rc == 1);
	assert(((struct ykp_config_t*)cfg)->command == SLOT_NDEF2);

	ykp_free_config(cfg);
	free(st);
}

static void _test_scanmap_no_config(void)
{
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = _test_init_st(4, 3, 0);

	char *argv[] = {
		"unittest", "-S", NULL
	};
	int argc = 2;

	int rc = _test_config(cfg, st, argc, argv);
	assert(rc == 1);
	assert(((struct ykp_config_t*)cfg)->command == SLOT_SCAN_MAP);

	ykp_free_config(cfg);
	free(st);
}

int main (void)
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
	_test_swap_with_slot();
	_test_slot_with_update();
	_test_swap_with_update();
	_test_ndef_for_neo_beta();
	_test_ndef_with_non_neo();
	_test_slot_two_with_neo_beta();
	_test_ndef2_with_neo();
	_test_ndef2_with_neo_beta();
	_test_scanmap_no_config();

	return 0;
}
