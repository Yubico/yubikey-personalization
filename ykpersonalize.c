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
#include <ykstatus.h>

const char *usage =
"Usage: ykpersonalize [options]\n"
"-sfile    save configuration to file instead of key.\n"
"          (if file is -, send to stdout)\n"
"-ifile    read configuration from file.\n"
"          (if file is -, read from stdin)\n"
"-ooption  change configuration option.  Possible option arguments are:\n"
"          salt=ssssssss       Salt to be used for key generation.  If\n"
"                              none is given, a unique random one will be\n"
"                              generated.\n"
"          fixed=fffffffffff   The fixed part to be included in the generated\n"
"                              ticket.  Can be up to 16 characters long.\n"
"          uid=uuuuuu          The uid part of the generated ticket.  Can\n"
"                              be up to 6 characters long.\n"
"          [-]tab-first        set/clear the TAB_FIRST ticket flag.\n"
"          [-]append-tab1      set/clear the APPEND_TAB1 ticket flag.\n"
"          [-]append-tab2      set/clear the APPEND_TAB1 ticket flag.\n"
"          [-]append-delay1    set/clear the APPEND_DELAY1 ticket flag.\n"
"          [-]append-delay2    set/clear the APPEND_DELAY2 ticket flag.\n"
"          [-]append-cr        set/clear the APPEND_CR ticket flag.\n"
"          [-]send-ref         set/clear the SEND_REF configuration flag.\n"
"          [-]ticket-first     set/clear the TICKET_FIRST configuration flag.\n"
"          [-]pacing-10ms      set/clear the PACING_10MS configuration flag.\n"
"          [-]pacing-20ms      set/clear the PACING_20MS configuration flag.\n"
"          [-]allow-hidtrig    set/clear the ALLOW_HIDTRIG configuration flag.\n"
"          [-]static-ticket    set/clear the STATIC_TICKET configuration flag.\n"
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

static void report_yk_error()
{
	if (ykp_errno)
		fprintf(stderr, "Yubikey personalization error: %s\n",
			ykp_strerror(ykp_errno));
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

main(int argc, char **argv)
{
	char c;
	FILE *inf = NULL; const char *infname = NULL;
	FILE *outf = NULL; const char *outfname = NULL;
	bool verbose = false;
	YUBIKEY *yk = NULL;
	CONFIG *cfg = ykp_create_config();
	STATUS *st = ykds_alloc();

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
			else if (strncmp(optarg, "fixed=", 6) == 0)
				ykp_set_fixed(cfg, optarg+6);
			else if (strncmp(optarg, "uid=", 4) == 0)
				ykp_set_uid(cfg, optarg+4);
			else if (strcmp(optarg, "tab-first") == 0)
				ykp_set_tktflag_TAB_FIRST(cfg, true);
			else if (strcmp(optarg, "-tab-first") == 0)
				ykp_set_tktflag_TAB_FIRST(cfg, false);
			else if (strcmp(optarg, "append-tab1") == 0)
				ykp_set_tktflag_APPEND_TAB1(cfg, true);
			else if (strcmp(optarg, "-append-tab1") == 0)
				ykp_set_tktflag_APPEND_TAB1(cfg, false);
			else if (strcmp(optarg, "append-tab2") == 0)
				ykp_set_tktflag_APPEND_TAB1(cfg, true);
			else if (strcmp(optarg, "-append-tab2") == 0)
				ykp_set_tktflag_APPEND_TAB1(cfg, false);
			else if (strcmp(optarg, "append-delay1") == 0)
				ykp_set_tktflag_APPEND_DELAY1(cfg, true);
			else if (strcmp(optarg, "-append-delay1") == 0)
				ykp_set_tktflag_APPEND_DELAY1(cfg, false);
			else if (strcmp(optarg, "append-delay2") == 0)
				ykp_set_tktflag_APPEND_DELAY2(cfg, true);
			else if (strcmp(optarg, "-append-delay2") == 0)
				ykp_set_tktflag_APPEND_DELAY2(cfg, false);
			else if (strcmp(optarg, "append-cr") == 0)
				ykp_set_tktflag_APPEND_CR(cfg, true);
			else if (strcmp(optarg, "-append-cr") == 0)
				ykp_set_tktflag_APPEND_CR(cfg, false);
			else if (strcmp(optarg, "send-ref") == 0)
				ykp_set_cfgflag_SEND_REF(cfg, true);
			else if (strcmp(optarg, "-send-ref") == 0)
				ykp_set_cfgflag_SEND_REF(cfg, false);
			else if (strcmp(optarg, "ticket-first") == 0)
				ykp_set_cfgflag_TICKET_FIRST(cfg, true);
			else if (strcmp(optarg, "-ticket-first") == 0)
				ykp_set_cfgflag_TICKET_FIRST(cfg, false);
			else if (strcmp(optarg, "pacing-10ms") == 0)
				ykp_set_cfgflag_PACING_10MS(cfg, true);
			else if (strcmp(optarg, "-pacing-10ms") == 0)
				ykp_set_cfgflag_PACING_10MS(cfg, false);
			else if (strcmp(optarg, "pacing-20ms") == 0)
				ykp_set_cfgflag_PACING_20MS(cfg, true);
			else if (strcmp(optarg, "-pacing-20ms") == 0)
				ykp_set_cfgflag_PACING_20MS(cfg, false);
			else if (strcmp(optarg, "allow-hidtrig") == 0)
				ykp_set_cfgflag_ALLOW_HIDTRIG(cfg, true);
			else if (strcmp(optarg, "-allow-hidtrig") == 0)
				ykp_set_cfgflag_ALLOW_HIDTRIG(cfg, false);
			else if (strcmp(optarg, "static-ticket") == 0)
				ykp_set_cfgflag_STATIC_TICKET(cfg, true);
			else if (strcmp(optarg, "-static-ticket") == 0)
				ykp_set_cfgflag_STATIC_TICKET(cfg, false);
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
			/* Assume the worst */
			exit_code = 2;

			if (verbose)
				printf("Attempting to write configuration to the yubikey...");
			if (!yk_init())
				break;

			if (!(yk = yk_open_first_key()))
				break;

			if (!yk_write_config(yk, cfg, NULL)) {
				if (verbose)
					printf(" failure\n");
				break;
			}

			if (verbose)
				printf(" success\n");

			if (yk_get_status(yk, st)) {
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
			} else
				break;

			ykp_write_config(cfg, writer, stdout);
		}

		exit_code = 0;
		error = false;
	} while(false);

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

	exit(exit_code);
}
