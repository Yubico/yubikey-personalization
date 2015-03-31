/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2012-2015 Yubico AB.
 * All rights reserved.
 *
 * Some basic code copied from ykchalresp.c.
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
#include <stdbool.h>

#include <yubikey.h>
#include <ykcore.h>
#include <ykstatus.h>
#include <ykpers-version.h>
#include <ykdef.h>

const char *usage =
	"Usage: ykinfo [options]\n"
	"\n"
	"Options :\n"
	"\n"
	"\t-s        Get serial in decimal from YubiKey\n"
	"\t-m        Get serial in modhex from YubiKey\n"
	"\t-H        Get serial in hex from YubiKey\n"
	"\t-v        Get version from YubiKey\n"
	"\t-t        Get touchlevel from YubiKey\n"
	"\t-1        Check if slot 1 is programmed\n"
	"\t-2        Check if slot 2 is programmed\n"
	"\t-p        Get programming sequence from YubiKey\n"
	"\t-i        Get vendor id of YubiKey\n"
	"\t-I        Get product id of YubiKey\n"
	"\t-a        Get all information above\n"
	"\t-c        Get capabilities from YubiKey\n"
	"\n"
	"\t-q        Only output information from YubiKey\n"
	"\n"
	"\t-V        Get the tool version\n"
	"\t-h        help (this text)\n"
	"\n"
	"\n"
	;
const char *optstring = "asmHvtpqhV12iIc";

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
		bool *serial_dec, bool *serial_modhex, bool *serial_hex,
		bool *version, bool *touch_level, bool *pgm_seq, bool *quiet,
		bool *slot1, bool *slot2, bool *vid, bool *pid, bool *capa,
		int *exit_code)
{
	int c;

	while((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'a':
			*serial_dec = true;
			*serial_modhex = true;
			*serial_hex = true;
			*version = true;
			*touch_level = true;
			*pgm_seq = true;
			*slot1 = true;
			*slot2 = true;
			*vid = true;
			*pid = true;
			break;
		case 's':
			*serial_dec = true;
			break;
		case 'm':
			*serial_modhex = true;
			break;
		case 'H':
			*serial_hex = true;
			break;
		case 'v':
			*version = true;
			break;
		case 't':
			*touch_level = true;
			break;
		case 'p':
			*pgm_seq = true;
			break;
		case 'q':
			*quiet = true;
			break;
		case '1':
			*slot1 = true;
			break;
		case '2':
			*slot2 = true;
			break;
		case 'i':
			*vid = true;
			break;
		case 'I':
			*pid = true;
			break;
		case 'c':
			*capa = true;
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

	if (!*serial_dec && !*serial_modhex && !*serial_hex &&
			!*version && !*touch_level && !*pgm_seq && !*slot1 && !*slot2 &&
			!*vid && !*pid && !*capa) {
		/* no options at all */
		fputs("You must give at least one option.\n", stderr);
		fputs(usage, stderr);
		return 0;
	}

	return 1;
}


int main(int argc, char **argv)
{
	YK_KEY *yk = 0;
	bool error = true;
	int exit_code = 0;

	/* Options */
	bool serial_dec = false;
	bool serial_modhex = false;
	bool serial_hex = false;
	bool version = false;
	bool touch_level = false;
	bool pgm_seq = false;
	bool slot1 = false;
	bool slot2 = false;
	bool vid = false;
	bool pid = false;
	bool capa = false;

	bool quiet = false;

	yk_errno = 0;

	if (! parse_args(argc, argv,
				&serial_dec, &serial_modhex, &serial_hex,
				&version, &touch_level, &pgm_seq, &quiet,
				&slot1, &slot2, &vid, &pid, &capa,
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

	if(serial_dec || serial_modhex || serial_hex) {
		unsigned int serial;
		int ret = yk_get_serial(yk, 1, 0, &serial);
		if(!ret) {
			exit_code = 1;
			goto err;
		}
		if(serial_dec) {
			if(!quiet)
				printf("serial: ");
			printf("%d\n", serial);
		}
		if(serial_modhex || serial_hex) {
			char buf[64];
			char hex_serial[64];
			char modhex_serial[64];
			char *ptr = buf;

			int chars = snprintf(buf + 1, 63, "%x", serial);
			if(chars % 2 == 1) {
				buf[0] = '0';
			} else {
				ptr += 1;
			}
			if(serial_hex) {
				if(!quiet)
					printf("serial_hex: ");
				printf("%s\n", ptr);
			}
			if(serial_modhex) {
				yubikey_hex_decode(hex_serial, ptr, strlen(ptr));
				yubikey_modhex_encode(modhex_serial, hex_serial, strlen(hex_serial));
				if(!quiet)
					printf("serial_modhex: ");
				printf("%s\n", modhex_serial);
			}
		}
	}
	if(version || touch_level || pgm_seq || slot1 || slot2) {
		YK_STATUS *st = ykds_alloc();
		if(!yk_get_status(yk, st)) {
			ykds_free(st);
			exit_code = 1;
			goto err;
		}

		if(version) {
			if(!quiet)
				printf("version: ");
			printf("%d.%d.%d\n", ykds_version_major(st), ykds_version_minor(st), ykds_version_build(st));
		}
		if(touch_level) {
			if(!quiet)
				printf("touch_level: ");
			printf("%d\n", ykds_touch_level(st));
		}
		if(pgm_seq) {
			if(!quiet)
				printf("programming_sequence: ");
			printf("%d\n", ykds_pgm_seq(st));
		}
		if(slot1) {
			if(!quiet)
				printf("slot1_status: ");
			printf("%d\n", (ykds_touch_level(st) & CONFIG1_VALID) == CONFIG1_VALID);
		}
		if(slot2) {
			if(!quiet)
				printf("slot2_status: ");
			printf("%d\n", (ykds_touch_level(st) & CONFIG2_VALID) == CONFIG2_VALID);
		}
		ykds_free(st);
	}
	if(vid || pid) {
		int vendor_id, product_id;
		if(!yk_get_key_vid_pid(yk, &vendor_id, &product_id)) {
			exit_code = 1;
			goto err;
		}
		if(vid) {
			if(!quiet)
				printf("vendor_id: ");
			printf("%x\n", vendor_id);
		}
		if(pid) {
			if(!quiet)
				printf("product_id: ");
			printf("%x\n", product_id);
		}
	}
	if(capa) {
		unsigned char buf[0xff];
		unsigned int len = 0xff;
		unsigned int i;
		if(!yk_get_capabilities(yk, 1, 0, buf, &len)) {
			exit_code = 1;
			goto err;
		}
		if(!quiet)
			printf("capabilities: ");
		for(i = 0; i < len; i++) {
			printf("%02x", buf[i]);
		}
		printf("\n");
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
