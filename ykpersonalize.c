/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008, Yubico AB
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

const char *usage =
"Usage: ykpersonalize [options]\n"
"-sfile    save configuration to file instead of key\n"
"          (if file is -, send to stdout)\n"
"-ifile    read configuration from file\n"
"          (if file is -, read from stdin)\n"
"-ooption  change configuration option.  Possible option arguments are:\n"
"          salt=ssssssss   Salt to be used for key generation.  If none\n"
"                          is given, a unique random one will be generated\n"
""
"-v        verbose\n"
"-h        help (this text)\n"
;
const char *optstring = "hi:o:s:v";

static int reader(char *buf, size_t count, void *stream)
{
	return (int)fread(buf, 1, count, (FILE *)stream);
}
static int writer(const char *buf, size_t count, void *stream)
{
	return (int)fwrite(buf, 1, count, (FILE *)stream);
}

main(int argc, char **argv)
{
	char c;
	FILE *inf = NULL; const char *infname = NULL;
	FILE *outf = NULL; const char *outfname = NULL;
	bool verbose = false;
	CONFIG *cfg = ykp_create_config();

	bool error = false;
	int exit_code = 0;

	if (!cfg) {
		fprintf(stderr, "Out of memory!\n");
		exit(1);
	}

	/* Options */
	char *salt = NULL;

	while((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'i':
			infname = optarg;
			break;
		case 's':
			outfname = optarg;
			break;
		case 'o':
			if (strncmp(optarg, "salt=", 5) == 0)
				salt = strdup(optarg+5);
			else {
				fprintf(stderr, "Unknown option '%s'\n",
					optarg);
				fprintf(stderr, usage);
				exit(1);
			}
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
		default:
			fprintf(stderr, usage);
			exit(0);
			break;
		}
	}

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
			exit(1);
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

	/* Using a do-while loop that never loops provides a practical
	   way to bail out on error without using goto... */
	do {
		/* Assume the worst */
		error = true;

		exit_code = 0;
		ykp_errno = 0;
		yk_errno = 0;

		if (inf) {
			if (!ykp_read_config(cfg, reader, inf))
				break;
		} else {
			char passphrasebuf[256]; size_t passphraselen;
			fprintf(stderr, "Passphrase to create AES key: ");
			fflush(stderr);
			fgets(passphrasebuf, sizeof(passphrasebuf), stdin);
			passphraselen = strlen(passphrasebuf);
			if (passphrasebuf[passphraselen - 1] == '\n')
				passphrasebuf[passphraselen - 1] == '\0';
			if (!ykp_AES_key_from_passphrase(cfg,
							 passphrasebuf, salt))
				break;
		}

		if (outf) {
			if (!ykp_write_config(cfg, writer, outf))
				break;
		} else {
			YUBIKEY *yk;

			/* Assume the worst */
			exit_code = 2;

			if (verbose)
				printf("Attempting to write configuration to the yubikey...");
			if (!yk_init())
				break;

			if (!(yk = yk_open_first_key()))
				break;

			if (yk_write_config(yk, cfg, NULL)) {
				if (verbose)
					printf(" success\n");
				ykp_write_config(cfg, writer, stdout);
				exit_code = 0;
			} else {
				printf(" failure\n");
			}
			if (!yk_close_key(yk))
				break;

			if (!yk_release())
				break;
		}
		error = false;
	} while(false);

	if (salt)
		free(salt);
	if (inf)
		fclose(inf);
	if (outf)
		fclose(outf);

	if (error) {
		if (ykp_errno)
			fprintf(stderr, "Yubikey personalization error: %s\n",
				ykp_strerror(ykp_errno));
		if (yk_errno) {
			if (yk_errno == YK_EUSBERR) {
				fprintf(stderr, "USB error: %s\n",
					usb_strerror());
			} else {
				fprintf(stderr, "Yubikey core error: %s\n",
					yk_strerror(yk_errno));
			}
		}
		if (exit_code)
			exit(exit_code);
		exit(1);
	}
	exit(0);
}
