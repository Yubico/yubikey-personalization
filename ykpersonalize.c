/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008-2012 Yubico AB
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
static int writer(const char *buf, size_t count, void *stream)
{
	return (int)fwrite(buf, 1, count, (FILE *)stream);
}

int main(int argc, char **argv)
{
	FILE *inf = NULL; const char *infname = NULL;
	FILE *outf = NULL; const char *outfname = NULL;
	bool verbose = false;
	bool aesviahash = false;
	bool use_access_code = false;
	unsigned char access_code[256];
	YK_KEY *yk = 0;
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = ykds_alloc();
	bool autocommit = false;

	/* Options */
	char *salt = NULL;
	char ndef_string[128] = {0};
	char ndef_type;

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

	if (!(yk_check_firmware_version(yk))) {
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
			     &autocommit, salt,
			     st, &verbose,
			     access_code, &use_access_code,
			     &aesviahash, &ndef_type, ndef_string,
			     &exit_code)) {
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
	} else if (! aesviahash && (ykp_command(cfg) == SLOT_CONFIG || ykp_command(cfg) == SLOT_CONFIG2)) {
		char passphrasebuf[256]; size_t passphraselen;
		fprintf(stderr, "Passphrase to create AES key: ");
		fflush(stderr);
		fgets(passphrasebuf, sizeof(passphrasebuf), stdin);
		passphraselen = strlen(passphrasebuf);
		if (passphrasebuf[passphraselen - 1] == '\n')
			passphrasebuf[passphraselen - 1] = '\0';
		if (!ykp_AES_key_from_passphrase(cfg,
						 passphrasebuf, salt))
			goto err;
	}

	if (outf) {
		if (!ykp_write_config(cfg, writer, outf))
			goto err;
	} else {
		char commitbuf[256]; size_t commitlen;

		if (ykp_command(cfg) == SLOT_SWAP) {
			fprintf(stderr, "Configuration in slot 1 and 2 will be swapped\n");
		} else if(ykp_command(cfg) == SLOT_NDEF) {
			fprintf(stderr, "New NDEF URI will be written\n");
		} else {
			if (ykp_command(cfg) == SLOT_CONFIG || ykp_command(cfg) == SLOT_CONFIG2) {
				fprintf(stderr, "Configuration data to be written to key configuration %d:\n\n", ykp_config_num(cfg));
			} else {
				fprintf(stderr, "Configuration data to be updated in key configuration %d:\n\n", ykp_command(cfg) == SLOT_UPDATE1 ? 1 : 2);
			}
			ykp_write_config(cfg, writer, stderr);
		}
		fprintf(stderr, "\nCommit? (y/n) [n]: ");
		if (autocommit) {
			strcpy(commitbuf, "yes");
			puts(commitbuf);
		} else {
			fgets(commitbuf, sizeof(commitbuf), stdin);
		}
		commitlen = strlen(commitbuf);
		if (commitbuf[commitlen - 1] == '\n')
			commitbuf[commitlen - 1] = '\0';
		if (strcmp(commitbuf, "y") == 0
		    || strcmp(commitbuf, "yes") == 0) {
			exit_code = 2;

			if (verbose)
				printf("Attempting to write configuration to the yubikey...");
			if(ykp_command(cfg) == SLOT_NDEF) {
				YK_NDEF *ndef = ykp_alloc_ndef();
				if(ndef_type == 'U') {
					ykp_construct_ndef_uri(ndef, ndef_string);
				} else if(ndef_type == 'T') {
					ykp_construct_ndef_text(ndef, ndef_string, "en", false);
				}
				if(use_access_code) {
					ykp_set_ndef_access_code(ndef, access_code);
				}
				if (!yk_write_ndef(yk, ndef)) {
					if (verbose)
						printf(" failure\n");
					goto err;
				}
				ykp_free_ndef(ndef);
			} else {
				if (!yk_write_command(yk,
							ykp_core_config(cfg), ykp_command(cfg),
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
