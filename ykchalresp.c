/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2011-2013 Yubico AB.
 * All rights reserved.
 *
 * Author : Fredrik Thulin <fredrik@yubico.com>
 *
 * Some basic code copied from ykpersonalize.c.
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
#include <unistd.h>
#include <time.h>

#include <yubikey.h>
#include <ykdef.h>
#include <ykcore.h>
#include <ykstatus.h>
#include <ykpers-version.h>

const char *usage =
	"Usage: ykchalresp [options] [challenge]\n"
	"\n"
	"Options :\n"
	"\n"
	"\t-1        Send challenge to slot 1. This is the default.\n"
	"\t-2        Send challenge to slot 2.\n"
	"\t-H        Send a 64 byte HMAC challenge. This is the default.\n"
	"\t-Y        Send a 6 byte Yubico challenge.\n"
	"\t-N        Abort if Yubikey requires button press.\n"
	"\t-x        Challenge is hex encoded.\n"
	"\t-t        Time based challenge (for TOTP)\n"
	"\t-6        Output 6 digit HOTP/TOTP code\n"
	"\t-8        Output 8 digit HOTP/TOTP code\n"
	"\n"
	"\t-v        verbose\n"
	"\t-V        tool version\n"
	"\t-h        help (this text)\n"
	"\n"
	"\n"
	;
const char *optstring = "1268xvhHtYNV";

static void report_yk_error(void)
{
	if (yk_errno) {
		if (yk_errno == YK_EUSBERR) {
			fprintf(stderr, "USB error: %s\n",
				yk_usb_strerror());
		} else {
			fprintf(stderr, "Yubikey core error: %s\n",
				yk_strerror(yk_errno));
		}
	}
}

static int parse_args(int argc, char **argv,
	       int *slot, bool *verbose,
	       unsigned char **challenge, unsigned int *challenge_len,
	       bool *hmac, bool *may_block, bool *totp, int *digits,
	       int *exit_code)
{
	int c;
	bool hex_encoded = false;

	while((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case '1':
			*slot = 1;
			break;
		case '2':
			*slot = 2;
			break;
		case 'H':
			*hmac = true;
			break;
		case 'N':
			*may_block = false;
			break;
		case 't':
			*totp = true;
			*hmac = true;
			break;
		case '6':
			*digits = 6;
			break;
		case '8':
			*digits = 8;
			break;
		case 'Y':
			*hmac = false;
			*totp = false;
			break;
		case 'x':
			hex_encoded = true;
			break;
		case 'v':
			*verbose = true;
			break;
		case 'V':
			fputs(YKPERS_VERSION_STRING "\n", stderr);
			*exit_code = 0;
			return 0;
		case 'h':
		default:
			fputs(usage, stderr);
			*exit_code = 0;
			return 0;
		}
	}

	if ((optind >= argc && !*totp) || (optind < argc && *totp)) {
		/* No challenge */
		fputs(usage, stderr);
		return 0;
	}
	if (*totp && *hmac) {
		unsigned int t_counter;
		static unsigned char t_buf[8];
		t_counter = (int) time(NULL);
		t_counter = t_counter / 30;
		memset(t_buf, 0, sizeof(t_buf));
		t_buf[7] = t_counter & 0x000000ff;
		t_buf[6] = (t_counter & 0x0000ff00) >> 8;
		t_buf[5] = (t_counter & 0x00ff0000) >>16;
		t_buf[4] = (t_counter & 0xff000000) >>24;
		*challenge = (unsigned char *) &t_buf;
		*challenge_len = 8;
	}
	else if (hex_encoded) {
		static unsigned char decoded[SHA1_MAX_BLOCK_SIZE];

		size_t strl = strlen(argv[optind]);

		if (strl > sizeof(decoded) * 2) {
			fprintf(stderr, "Hex-encoded challenge too long (max %lu chars)\n",
				sizeof(decoded) * 2);
			return 0;
		}

		if (strl % 2 != 0) {
			fprintf(stderr, "Odd number of characters in hex-encoded challenge\n");
			return 0;
		}

		memset(decoded, 0, sizeof(decoded));

		if (yubikey_hex_p(argv[optind])) {
			yubikey_hex_decode((char *)decoded, argv[optind], sizeof(decoded));
		} else {
			fprintf(stderr, "Bad hex-encoded string '%s'\n", argv[optind]);
			return 0;
		}
		*challenge = (unsigned char *) &decoded;
		*challenge_len = strl / 2;
	} else {
		*challenge = (unsigned char *) argv[optind];
		*challenge_len = strlen(argv[optind]);
	}

	return 1;
}

static int check_firmware(YK_KEY *yk, bool verbose)
{
	YK_STATUS *st = ykds_alloc();

	if (!yk_get_status(yk, st)) {
		ykds_free(st);
		return 0;
	}

	if (verbose) {
		printf("Firmware version %d.%d.%d\n",
		       ykds_version_major(st),
		       ykds_version_minor(st),
		       ykds_version_build(st));
		fflush(stdout);
	}

	if (ykds_version_major(st) < 2 ||
	    (ykds_version_major(st) == 2
	     && ykds_version_minor(st) < 2)) {
		fprintf(stderr, "Challenge-response not supported before YubiKey 2.2.\n");
		ykds_free(st);
		return 0;
	}

	free(st);
	return 1;
}

static int challenge_response(YK_KEY *yk, int slot,
		       unsigned char *challenge, unsigned int len,
		       bool hmac, bool may_block, bool verbose, int digits )
{
	unsigned char response[SHA1_MAX_BLOCK_SIZE];
	unsigned char output_buf[(SHA1_MAX_BLOCK_SIZE * 2) + 1];
	int yk_cmd;
	unsigned int expect_bytes = 0;
	unsigned int offset;
	unsigned int bin_code;
	memset(response, 0, sizeof(response));
	memset(output_buf, 0, sizeof(output_buf));

	if (verbose) {
		fprintf(stderr, "Sending %i bytes %s challenge to slot %i\n", len, (hmac == true)?"HMAC":"Yubico", slot);
	}

	switch(slot) {
	case 1:
		yk_cmd = (hmac == true) ? SLOT_CHAL_HMAC1 : SLOT_CHAL_OTP1;
		break;
	case 2:
		yk_cmd = (hmac == true) ? SLOT_CHAL_HMAC2 : SLOT_CHAL_OTP2;
		break;
	default:
		return 0;
	}

	if(! yk_challenge_response(yk, yk_cmd, may_block, len,
				challenge, sizeof(response), response)) {
		return 0;
	}

	/* HMAC responses are 160 bits, Yubico 128 */
	expect_bytes = (hmac == true) ? 20 : 16;

	if(digits && hmac){
		offset   =  response[19] & 0xf ;
		bin_code = (response[offset]  & 0x7f) << 24
			| (response[offset+1] & 0xff) << 16
			| (response[offset+2] & 0xff) <<  8
			| (response[offset+3] & 0xff) ;
		if(digits == 8){
			bin_code = bin_code % 100000000;
			printf("%08u\n", bin_code);
			return 1;
		}
		bin_code = bin_code % 1000000;
		printf("%06i\n", bin_code);
		return 1;
	}
	if (hmac) {
		yubikey_hex_encode((char *)output_buf, (char *)response, expect_bytes);
	} else {
		yubikey_modhex_encode((char *)output_buf, (char *)response, expect_bytes);
	}
	printf("%s\n", output_buf);

	return 1;
}

int main(int argc, char **argv)
{
	YK_KEY *yk = 0;
	bool error = true;
	int exit_code = 0;

	/* Options */
	bool verbose = false;
	bool hmac = true;
	bool may_block = true;
	bool totp = false;
	int digits = 0;
	unsigned char *challenge;
	unsigned int challenge_len;
	int slot = 1;

	yk_errno = 0;

	if (! parse_args(argc, argv,
			 &slot, &verbose,
			 &challenge, &challenge_len,
			 &hmac, &may_block, &totp, &digits,
			 &exit_code))
		exit(exit_code);

	if (!yk_init()) {
		exit_code = 1;
		goto err;
	}

	if (!(yk = yk_open_first_key())) {
		exit_code = 1;
		goto err;
	}

	if (! check_firmware(yk, verbose)) {
		exit_code = 1;
		goto err;
	}

	if (! challenge_response(yk, slot,
				 challenge, challenge_len,
				 hmac, may_block, verbose, digits)) {
		exit_code = 1;
		goto err;
	}

	exit_code = 0;
	error = false;

err:
	if (error || exit_code != 0) {
		report_yk_error();
	}

	if (yk && !yk_close_key(yk)) {
		report_yk_error();
		exit_code = 2;
	}

	if (!yk_release()) {
		report_yk_error();
		exit_code = 2;
	}

	exit(exit_code);
}
