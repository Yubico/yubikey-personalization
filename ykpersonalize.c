/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008, 2009, 2010, Yubico AB
 * Copyright (c) 2010  Tollef Fog Heen <tfheen@err.no>
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
#include <yubikey.h> /* To get yubikey_modhex_encode and yubikey_hex_encode */

const char *usage =
"Usage: ykpersonalize [options]\n"
"-1        change the first configuration.  This is the default and\n"
"          is normally used for true OTP generation.\n"
"          In this configuration, TKTFLAG_APPEND_CR is set by default.\n"
"-2        change the second configuration.  This is for Yubikey II only\n"
"          and is then normally used for static key generation.\n"
"          In this configuration, TKTFLAG_APPEND_CR, CFGFLAG_STATIC_TICKET,\n"
"          CFGFLAG_STRONG_PW1, CFGFLAG_STRONG_PW2 and CFGFLAG_MAN_UPDATE\n"
"          are set by default.\n"
"-sFILE    save configuration to FILE instead of key.\n"
"          (if FILE is -, send to stdout)\n"
"-iFILE    read configuration from FILE.\n"
"          (if FILE is -, read from stdin)\n"
"-aXXX..   A 32 char hex value (not modhex) of a fixed AES key to use\n"
"-cXXX..   A 12 char hex value to use as access code for programming\n"
"          (this does NOT SET the access code, that's done with -oaccess=)\n"
"-oOPTION  change configuration option.  Possible OPTION arguments are:\n"
"          salt=ssssssss       Salt to be used when deriving key from a\n
"                              password.  If none is given, a unique random\n"
"                              one will be generated.\n"
"          fixed=xxxxxxxxxxx   The public identity of key, in MODHEX.\n"
"                              This is 0-16 characters long.\n"
"          uid=xxxxxx          The uid part of the generated ticket, in HEX.\n"
"                              MUST be 12 characters long.\n"
"          access=xxxxxxxxxxx  New access code to set, in HEX.\n"
"                              MUST be 12 characters long.\n"
"\n"
"          Ticket flags for all firmware versions:\n"
"          [-]tab-first           set/clear TAB_FIRST\n"
"          [-]append-tab1         set/clear APPEND_TAB1\n"
"          [-]append-tab2         set/clear APPEND_TAB2\n"
"          [-]append-delay1       set/clear APPEND_DELAY1\n"
"          [-]append-delay2       set/clear APPEND_DELAY2\n"
"          [-]append-cr           set/clear APPEND_CR\n"
"\n"
"          Ticket flags for firmware version 2.0 and above:\n"
"          [-]protect-cfg2        set/clear PROTECT_CFG2\n"
"\n"
"          Ticket flags for firmware version 2.1 and above:\n"
"          [-]oath-hotp           set/clear OATH_HOTP\n"
"\n"
"          Configuration flags for all firmware versions:\n"
"          [-]send-ref            set/clear SEND_REF\n"
"          [-]pacing-10ms         set/clear PACING_10MS\n"
"          [-]pacing-20ms         set/clear PACING_20MS\n"
"          [-]static-ticket       set/clear STATIC_TICKET\n"
"\n"
"          Configuration flags for firmware version 1.x only:\n"
"          [-]ticket-first        set/clear TICKET_FIRST\n"
"          [-]allow-hidtrig       set/clear ALLOW_HIDTRIG\n"
"\n"
"          Configuration flags for firmware version 2.0 and above:\n"
"          [-]short-ticket        set/clear SHORT_TICKET\n"
"          [-]strong-pw1          set/clear STRONG_PW1\n"
"          [-]strong-pw2          set/clear STRONG_PW2\n"
"          [-]man-update          set/clear MAN_UPDATE\n"
"\n"
"          Configuration flags for firmware version 2.1 and above:\n"
"          [-]oath-hotp8          set/clear OATH_HOTP8\n"
"          [-]oath-fixed-modhex1  set/clear OATH_FIXED_MODHEX1\n"
"          [-]oath-fixed-modhex2  set/clear OATH_FIXED_MODHEX2\n"
"          [-]oath-fixed-modhex   set/clear OATH_MODHEX\n"
"\n"
"-y        always commit (do not prompt)\n"
"\n"
"-v        verbose\n"
"-h        help (this text)\n"
;
const char *optstring = "12a:c:hi:o:s:vy";

static int reader(char *buf, size_t count, void *stream)
{
	return (int)fread(buf, 1, count, (FILE *)stream);
}
static int writer(const char *buf, size_t count, void *stream)
{
	return (int)fwrite(buf, 1, count, (FILE *)stream);
}

static int hex_modhex_decode(unsigned char *result, size_t *resultlen,
			     const char *str, size_t strl,
			     size_t minsize, size_t maxsize,
			     bool primarily_modhex)
{
	if (strl >= 2) {
		if (strncmp(str, "m:", 2) == 0
		    || strncmp(str, "M:", 2) == 0) {
			str += 2;
			strl -= 2;
			primarily_modhex = true;
		} else if (strncmp(str, "h:", 2) == 0
			   || strncmp(str, "H:", 2) == 0) {
			str += 2;
			strl -= 2;
			primarily_modhex = false;
		}
	}

	if ((strl % 2 != 0) || (strl < minsize) || (strl > maxsize)) {
		return -1;
	}

	*resultlen = strl / 2;
	if (primarily_modhex) {
		if (yubikey_modhex_p(str)) {
			yubikey_modhex_decode((char *)result, str, strl);
			return 1;
		}
	} else {
		if (yubikey_hex_p(str)) {
			yubikey_hex_decode((char *)result, str, strl);
			return 1;
		}
	}

	return 0;
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

int main(int argc, char **argv)
{
	char c;
	FILE *inf = NULL; const char *infname = NULL;
	FILE *outf = NULL; const char *outfname = NULL;
	bool verbose = false;
	bool aesviahash = false; const char *aeshash = NULL;
	bool use_access_code = false, new_access_code = false;
	unsigned char access_code[256];
	YK_KEY *yk = 0;
	YKP_CONFIG *cfg = ykp_create_config();
	YK_STATUS *st = ykds_alloc();
	bool autocommit = false;

	bool error = false;
	int exit_code = 0;

	/* Options */
	char *salt = NULL;

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

	if (!ykp_configure_for(cfg, 1, st))
		goto err;

	while((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case '1':
			if (!ykp_configure_for(cfg, 1, st))
				goto err;
			break;
		case '2':
			if (!ykp_configure_for(cfg, 2, st))
				goto err;
			break;
		case 'i':
			infname = optarg;
			break;
		case 's':
			outfname = optarg;
			break;
		case 'a':
			aesviahash = true;
			aeshash = optarg;
			break;
		case 'c': {
			size_t access_code_len = 0;
			int rc = hex_modhex_decode(access_code, &access_code_len,
						   optarg, strlen(optarg),
						   12, 12, false);
			if (rc <= 0) {
				fprintf(stderr,
					"Invalid access code string: %s\n",
					optarg);
				exit_code = 1;
				goto err;
			}
			if (!new_access_code)
				ykp_set_access_code(cfg,
						    access_code,
						    access_code_len);
			use_access_code = true;
			break;
		}
		case 'o':
			if (strncmp(optarg, "salt=", 5) == 0)
				salt = strdup(optarg+5);
			else if (strncmp(optarg, "fixed=", 6) == 0) {
				const char *fixed = optarg+6;
				size_t fixedlen = strlen (fixed);
				unsigned char fixedbin[256];
				size_t fixedbinlen = 0;
				int rc = hex_modhex_decode(fixedbin, &fixedbinlen,
							   fixed, fixedlen,
							   0, 16, true);
				if (rc <= 0) {
					fprintf(stderr,
						"Invalid fixed string: %s\n",
						fixed);
					exit_code = 1;
					goto err;
				}
				ykp_set_fixed(cfg, fixedbin, fixedbinlen);
			}
			else if (strncmp(optarg, "uid=", 4) == 0) {
				const char *uid = optarg+4;
				size_t uidlen = strlen (uid);
				unsigned char uidbin[256];
				size_t uidbinlen = 0;
				int rc = hex_modhex_decode(uidbin, &uidbinlen,
							   uid, uidlen,
							   12, 12, false);
				if (rc <= 0) {
					fprintf(stderr,
						"Invalid uid string: %s\n",
						uid);
					exit_code = 1;
					goto err;
				}
				ykp_set_uid(cfg, uidbin, uidbinlen);
			}
			else if (strncmp(optarg, "access=", 7) == 0) {
				const char *acc = optarg+7;
				size_t acclen = strlen (acc);
				unsigned char accbin[256];
				size_t accbinlen = 0;
				int rc = hex_modhex_decode (accbin, &accbinlen,
							    acc, acclen,
							    12, 12, false);
				if (rc <= 0) {
					fprintf(stderr,
						"Invalid access code string: %s\n",
						acc);
					exit_code = 1;
					goto err;
				}
				ykp_set_access_code(cfg, accbin, accbinlen);
				new_access_code = true;
			}
#define TKTFLAG(o, f)						\
			else if (strcmp(optarg, o) == 0)	\
				ykp_set_tktflag_##f(cfg, true); \
			else if (strcmp(optarg, "-" o) == 0)   \
				ykp_set_tktflag_##f(cfg, false)
			TKTFLAG("tab-first", TAB_FIRST);
			TKTFLAG("append-tab1", APPEND_TAB1);
			TKTFLAG("append-tab2", APPEND_TAB2);
			TKTFLAG("append-delay1", APPEND_DELAY1);
			TKTFLAG("append-delay2", APPEND_DELAY2);
			TKTFLAG("append-cr", APPEND_CR);
			TKTFLAG("protect-cfg2", PROTECT_CFG2);
			TKTFLAG("oath-hotp", OATH_HOTP);
#undef TKTFLAG

#define CFGFLAG(o, f) \
			else if (strcmp(optarg, o) == 0)	\
				ykp_set_cfgflag_##f(cfg, true); \
			else if (strcmp(optarg, "-" o) == 0)   \
				ykp_set_cfgflag_##f(cfg, false)
			CFGFLAG("send-ref", SEND_REF);
			CFGFLAG("ticket-first", TICKET_FIRST);
			CFGFLAG("pacing-10ms", PACING_10MS);
			CFGFLAG("pacing-20ms", PACING_20MS);
			CFGFLAG("allow-hidtrig", ALLOW_HIDTRIG);
			CFGFLAG("static-ticket", STATIC_TICKET);
			CFGFLAG("short-ticket", SHORT_TICKET);
			CFGFLAG("strong-pw1", STRONG_PW1);
			CFGFLAG("strong-pw2", STRONG_PW2);
			CFGFLAG("man-update", MAN_UPDATE);
			CFGFLAG("oath-hotp8", OATH_HOTP8);
			CFGFLAG("oath-fixed-modhex1", OATH_FIXED_MODHEX1);
			CFGFLAG("oath-fixed-modhex2", OATH_FIXED_MODHEX2);
			CFGFLAG("oath-fixed-modhex", OATH_FIXED_MODHEX);
#undef CFGFLAG
			else {
				fprintf(stderr, "Unknown option '%s'\n",
					optarg);
				fputs(usage, stderr);
				exit_code = 1;
				goto err;
			}
			break;
		case 'v':
			verbose = true;
			break;
		case 'y':
			autocommit = true;
			break;
		case 'h':
		default:
			fputs(usage, stderr);
			exit_code = 0;
			goto err;
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
	} else if (aesviahash) {
		if (ykp_AES_key_from_hex(cfg, aeshash)) {
			fprintf(stderr, "Bad AES key: %s\n", aeshash);
			fflush(stderr);
			goto err;
		}
	} else {
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

		fprintf(stderr, "Configuration data to be written to key configuration %d:\n\n", ykp_config_num(cfg));
		ykp_write_config(cfg, writer, stderr);
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
			if (!yk_write_config(yk,
					     ykp_core_config(cfg), ykp_config_num(cfg),
					     use_access_code ? access_code : NULL)) {
				if (verbose)
					printf(" failure\n");
				goto err;
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
