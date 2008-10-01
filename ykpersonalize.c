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
	FILE *inf = NULL;
	FILE *outf = NULL;
	bool verbose = false;
	CONFIG *cfg = ykp_create_config();

	/* Options */
	char *salt = NULL;

	while((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'i':
			if (strcmp(optarg, "-") == 0)
				inf = stdin;
			else
				inf = fopen(optarg, "r");
			if (inf == NULL) {
				fprintf(stderr,
					"Couldn't open %s for reading: %s\n",
					optarg,
					strerror(errno));
				exit(1);
			}
			break;
		case 's':
			if (strcmp(optarg, "-") == 0)
				outf = stdout;
			else
				outf = fopen(optarg, "r");
			if (outf == NULL) {
				fprintf(stderr,
					"Couldn't open %s for writing: %s\n",
					optarg,
					strerror(errno));
				exit(1);
			}
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
		case 'h':
		default:
			fprintf(stderr, usage);
			exit(0);
			break;
		}
	}

	if (inf) {
		ykp_read_config(cfg, reader, inf);
		fclose(inf);
	} else {
		char passphrasebuf[256]; size_t passphraselen;
		fprintf(stderr, "Passphrase to create AES key: ");
		fflush(stderr);
		fgets(passphrasebuf, sizeof(passphrasebuf), stdin);
		passphraselen = strlen(passphrasebuf);
		if (passphrasebuf[passphraselen - 1] == '\n')
			passphrasebuf[passphraselen - 1] == '\0';
		ykp_AES_key_from_passphrase(cfg, passphrasebuf, salt);
	}

	if (outf) {
		ykp_write_config(cfg, writer, outf);
		fclose(outf);
	} else {
		/* Output to key, and that's a different story! */
	}

	if (salt)
		free(salt);
}
