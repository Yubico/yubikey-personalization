/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008-2013 Yubico AB
 * Copyright (c) 2010 Tollef Fog Heen <tfheen@err.no>
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

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <ykpers.h>
#include <ykdef.h>

#include "ykpers-args.h"

static int reader(char *buf, size_t count, void *stream)
{
	return (int)fread(buf, 1, count, (FILE *)stream);
}

int main(int argc, char **argv)
{
	FILE *inf = NULL; const char *infname = NULL;
	FILE *outf = NULL; const char *outfname = NULL;
	int data_format = YKP_FORMAT_LEGACY;
	bool verbose = false;
	bool aesviahash = false;
	bool use_access_code = false;
	unsigned char access_code[256];
	unsigned char scan_codes[sizeof(SCAN_MAP)];
	YK_KEY *yk = 0;
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = ykds_alloc();
	bool autocommit = false;
	char exported_data[1024];

	/* Options */
	char *salt = NULL;
	char ndef_string[128] = {0};
	char ndef_type = 0;
	unsigned char usb_mode = 0;
	bool zap = false;

	bool error = false;
	int exit_code = 0;

	ykp_errno = 0;
	yk_errno = 0;

	/* Assume the worst */
	error = true;

	if (!yk_init()) {
		exit_code = 1;
		goto err;
	}

	if (argc == 2 && strcmp (argv[1], "-h") == 0) {
		fputs(usage, stderr);
		goto err;
	}

	if (!(yk = yk_open_first_key())) {
		exit_code = 1;
		goto err;
	}

	if (!yk_get_status(yk, st)) {
		exit_code = 1;
		goto err;
	}

	printf("Firmware version %d.%d.%d Touch level %d ",
	       ykds_version_major(st),
	       ykds_version_minor(st),
	       ykds_version_build(st),
	       ykds_touch_level(st));
	if (ykds_pgm_seq(st))
		printf("Program sequence %d\n",
		       ykds_pgm_seq(st));
	else
		printf("Unconfigured\n");

	if (!(yk_check_firmware_version2(st))) {
		if (yk_errno == YK_EFIRMWARE) {
			printf("Unsupported firmware revision - some "
			       "features may not be available\n"
			       "Please see \n"
			       "http://code.google.com/p/yubikey-personalization/wiki/Compatibility\n"
			       "for more information.\n");
		} else {
			goto err;
		}
	}

	/* Parse all arguments in a testable way */
	if (! args_to_config(argc, argv, cfg, yk,
			     &infname, &outfname,
			     &data_format,
			     &autocommit, salt,
			     st, &verbose,
			     access_code, &use_access_code,
			     &aesviahash, &ndef_type, ndef_string,
			     &usb_mode, &zap, scan_codes, &exit_code)) {
		goto err;
	}

	if (verbose && (ykds_version_major(st) > 2 ||
			(ykds_version_major(st) == 2 &&
			 ykds_version_minor(st) >= 2) ||
			(ykds_version_major(st) == 2 && // neo has serial functions
			 ykds_version_minor(st) == 1 &&
			 ykds_version_build(st) >= 4))) {
		unsigned int serial;
		if (! yk_get_serial(yk, 0, 0, &serial)) {
			printf ("Failed to read serial number (serial-api-visible disabled?).\n");

		} else {
			printf ("Serial number : %i\n", serial);
		}
	}

	printf ("\n");

	if (infname) {
		if (strcmp(infname, "-") == 0)
			inf = stdin;
		else
			inf = fopen(infname, "r");
		if (inf == NULL) {
			fprintf(stderr,
				"Couldn't open %s for reading: %s\n",
				infname,
				strerror(errno));
			exit_code = 1;
			goto err;
		}
	}

	if (outfname) {
		if (strcmp(outfname, "-") == 0)
			outf = stdout;
		else
			outf = fopen(outfname, "w");
		if (outf == NULL) {
			fprintf(stderr,
				"Couldn't open %s for writing: %s\n",
				outfname,
				strerror(errno));
			exit(1);
		}
	}

	if (inf) {
		if (!ykp_read_config(cfg, reader, inf))
			goto err;
	} else if (! aesviahash && ! zap && (ykp_command(cfg) == SLOT_CONFIG || ykp_command(cfg) == SLOT_CONFIG2)) {
		char passphrasebuf[256]; size_t passphraselen;
		fprintf(stderr, "Passphrase to create AES key: ");
		fflush(stderr);
		if (!fgets(passphrasebuf, sizeof(passphrasebuf), stdin))
		{
			perror ("fgets");
			exit_code = 1;
			goto err;
		}
		passphraselen = strlen(passphrasebuf);
		if (passphrasebuf[passphraselen - 1] == '\n')
			passphrasebuf[passphraselen - 1] = '\0';
		if (!ykp_AES_key_from_passphrase(cfg,
						 passphrasebuf, salt))
			goto err;
	}

	ykp_export_config(cfg, exported_data, 1024, data_format);
	if (outf) {
		if(!(fwrite(exported_data, 1, strlen(exported_data), outf))) {
			goto err;
		}
	} else {
		char commitbuf[256]; size_t commitlen;

		if (ykp_command(cfg) == SLOT_SWAP) {
			fprintf(stderr, "Configuration in slot 1 and 2 will be swapped\n");
		} else if(ykp_command(cfg) == SLOT_NDEF || ykp_command(cfg) == SLOT_NDEF2) {
			fprintf(stderr, "New NDEF will be written as:\n%s\n", ndef_string);
		} else if(ykp_command(cfg) == SLOT_DEVICE_CONFIG) {
			fprintf(stderr, "The USB mode will be set to: 0x%x\n", usb_mode);
		} else if(ykp_command(cfg) == SLOT_SCAN_MAP) {
			fprintf(stderr, "A new scanmap will be written.\n");
		} else if(zap) {
			fprintf(stderr, "Configuration in slot %d will be deleted\n", ykp_config_num(cfg));
		} else {
			if (ykp_command(cfg) == SLOT_CONFIG || ykp_command(cfg) == SLOT_CONFIG2) {
				fprintf(stderr, "Configuration data to be written to key configuration %d:\n\n", ykp_config_num(cfg));
			} else {
				fprintf(stderr, "Configuration data to be updated in key configuration %d:\n\n", ykp_command(cfg) == SLOT_UPDATE1 ? 1 : 2);
			}
			fwrite(exported_data, 1, strlen(exported_data), stderr);
		}
		fprintf(stderr, "\nCommit? (y/n) [n]: ");
		if (autocommit) {
			strcpy(commitbuf, "yes");
			puts(commitbuf);
		} else {
			if (!fgets(commitbuf, sizeof(commitbuf), stdin))
			{
				perror ("fgets");
				exit_code;
				goto err;
			}
		}
		commitlen = strlen(commitbuf);
		if (commitbuf[commitlen - 1] == '\n')
			commitbuf[commitlen - 1] = '\0';
		if (strcmp(commitbuf, "y") == 0
		    || strcmp(commitbuf, "yes") == 0) {
			exit_code = 2;

			if (verbose)
				printf("Attempting to write configuration to the yubikey...");
			if(ykp_command(cfg) == SLOT_NDEF || ykp_command(cfg) == SLOT_NDEF2) {
				YK_NDEF *ndef = ykp_alloc_ndef();
				int confnum = 1;
				if(ndef_type == 'U') {
					ykp_construct_ndef_uri(ndef, ndef_string);
				} else if(ndef_type == 'T') {
					ykp_construct_ndef_text(ndef, ndef_string, "en", false);
				}
				if(use_access_code) {
					ykp_set_ndef_access_code(ndef, access_code);
				}
				if(ykp_command(cfg) == SLOT_NDEF2) {
					confnum = 2;
				}
				if (!yk_write_ndef2(yk, ndef, confnum)) {
					if (verbose)
						printf(" failure\n");
					goto err;
				}
				ykp_free_ndef(ndef);
			} else if(ykp_command(cfg) == SLOT_DEVICE_CONFIG) {
				YK_DEVICE_CONFIG *device_config = ykp_alloc_device_config();
				ykp_set_device_mode(device_config, usb_mode);
				if(!yk_write_device_config(yk, device_config)) {
					if(verbose)
						printf(" failure\n");
					goto err;
				}
				ykp_free_device_config(device_config);


			} else if(ykp_command(cfg) == SLOT_SCAN_MAP) {
				if(!yk_write_scan_map(yk, scan_codes)) {
					if(verbose)
						printf(" failure\n");
					goto err;
				}
			} else {
				YK_CONFIG *ycfg = NULL;
				/* if we're deleting a slot we send the configuration as NULL */
				if (!zap) {
					ycfg = ykp_core_config(cfg);
				}
				if (!yk_write_command(yk,
							ycfg, ykp_command(cfg),
							use_access_code ? access_code : NULL)) {
					if (verbose)
						printf(" failure\n");
					goto err;
				}
			}

			if (verbose)
				printf(" success\n");
		}
	}

	exit_code = 0;
	error = false;

err:
	if (error) {
		report_yk_error();
	}

	if (salt)
		free(salt);
	if (st)
		free(st);
	if (inf)
		fclose(inf);
	if (outf)
		fclose(outf);

	if (yk && !yk_close_key(yk)) {
		report_yk_error();
		exit_code = 2;
	}

	if (!yk_release()) {
		report_yk_error();
		exit_code = 2;
	}

	if (cfg)
		ykp_free_config(cfg);

	exit(exit_code);
}
