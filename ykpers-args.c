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

#include <ykcore_lcl.h>
#include <ykpers.h>
#include <yubikey.h> /* To get yubikey_modhex_encode and yubikey_hex_encode */
#include <ykdef.h>
#include "ykpers-args.h"

#define YUBICO_OATH_VENDOR_ID_HEX	0xe1	/* UB as hex */
#define YUBICO_HOTP_EVENT_TOKEN_TYPE	0x63	/* HE as hex */

const char *usage =
"Usage: ykpersonalize [options]\n"
"-u        update configuration without overwriting.  This is only available\n"
"          in YubiKey 2.3 and later.  EXTFLAG_ALLOW_UPDATE will be set by\n"
"          default\n"
"-1        change the first configuration.  This is the default and\n"
"          is normally used for true OTP generation.\n"
"          In this configuration, TKTFLAG_APPEND_CR is set by default.\n"
"-2        change the second configuration.  This is for Yubikey II only\n"
"          and is then normally used for static key generation.\n"
"          In this configuration, TKTFLAG_APPEND_CR, CFGFLAG_STATIC_TICKET,\n"
"          CFGFLAG_STRONG_PW1, CFGFLAG_STRONG_PW2 and CFGFLAG_MAN_UPDATE\n"
"          are set by default.\n"
"-x        swap the configuration in slot 1 and 2.  This is for YubiKey 2.3\n"
"          and newer only\n"
"-sFILE    save configuration to FILE instead of key.\n"
"          (if FILE is -, send to stdout)\n"
"-iFILE    read configuration from FILE.\n"
"          (if FILE is -, read from stdin)\n"
"-aXXX..   The AES secret key as a 32 (or 40 for OATH-HOTP/HMAC CHAL-RESP)\n"
"          char hex value (not modhex)\n"
"-cXXX..   A 12 char hex value (not modhex) to use as access code for programming\n"
"          (this does NOT SET the access code, that's done with -oaccess=)\n"
"-nXXX..   Write NDEF type 2 URI to YubiKey NEO, must be used on it's own\n"
"-tXXX..   Write NDEF type 2 text to YubiKey NEO, must be used on it's own\n"
"-oOPTION  change configuration option.  Possible OPTION arguments are:\n"
"          salt=ssssssss       Salt to be used when deriving key from a\n"
"                              password.  If none is given, a unique random\n"
"                              one will be generated.\n"
"          fixed=xxxxxxxxxxx   The public identity of key, in MODHEX.\n"
"                              This is 0-16 characters long.\n"
"          uid=xxxxxx          The uid part of the generated ticket, in HEX.\n"
"                              MUST be 12 characters long.\n"
"          access=xxxxxxxxxxx  New access code to set, in HEX.\n"
"                              MUST be 12 characters long.\n"
"          oath-imf=IMF        OATH Initial Moving Factor to use.\n"
"          oath-id[=h:OOTT...] OATH Token Identifier (none for serial-based)\n"
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
"          Ticket flags for firmware version 2.2 and above:\n"
"          [-]chal-resp           set/clear CHAL_RESP\n"
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
"          Configuration flags for firmware version 2.2 and above:\n"
"          [-]chal-yubico         set/clear CHAL_YUBICO\n"
"          [-]chal-hmac           set/clear CHAL_HMAC\n"
"          [-]hmac-lt64           set/clear HMAC_LT64\n"
"          [-]chal-btn-trig       set/clear CHAL_BTN_TRIG\n"
"\n"
"          Extended flags for firmware version 2.2 and above:\n"
"          [-]serial-btn-visible  set/clear SERIAL_BTN_VISIBLE\n"
"          [-]serial-usb-visible  set/clear SERIAL_USB_VISIBLE\n"
"          [-]serial-api-visible  set/clear SERIAL_API_VISIBLE\n"
"\n"
"          Extended flags for firmware version 2.3 and above:\n"
"          [-]use-numeric-keypad  set/clear USE_NUMERIC_KEYPAD\n"
"          [-]fast-trig           set/clear FAST_TRIG\n"
"          [-]allow-update        set/clear ALLOW_UPDATE\n"
"          [-]dormant             set/clear DORMANT\n"
"\n"
"-y        always commit (do not prompt)\n"
"\n"
"-v        verbose\n"
"-h        help (this text)\n"
;
const char *optstring = "u12xa:c:n:t:hi:o:s:vy";

static const YK_CONFIG default_config1 = {
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* fixed */
        { 0, 0, 0, 0, 0, 0 },   /* uid */
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* key */
        { 0, 0, 0, 0, 0, 0 },   /* accCode */
        0,                      /* fixedSize */
        0,                      /* extFlags */
        TKTFLAG_APPEND_CR,      /* tktFlags */
        0,                      /* cfgFlags */
	{0},                    /* ctrOffs */
        0                       /* crc */
};

static const YK_CONFIG default_config2 = {
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* fixed */
        { 0, 0, 0, 0, 0, 0 },   /* uid */
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* key */
        { 0, 0, 0, 0, 0, 0 },   /* accCode */
        0,                      /* fixedSize */
        0,                      /* extFlags */
        TKTFLAG_APPEND_CR,      /* tktFlags */
        /* cfgFlags */
        CFGFLAG_STATIC_TICKET | CFGFLAG_STRONG_PW1 | CFGFLAG_STRONG_PW2 | CFGFLAG_MAN_UPDATE,
	{0},                    /* ctrOffs */
        0                       /* crc */
};

static const YK_CONFIG default_update = {
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* fixed */
        { 0, 0, 0, 0, 0, 0 },   /* uid */
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* key */
        { 0, 0, 0, 0, 0, 0 },   /* accCode */
        0,                      /* fixedSize */
        EXTFLAG_ALLOW_UPDATE,   /* extFlags */
        TKTFLAG_APPEND_CR,      /* tktFlags */
        0,                      /* cfgFlags */
	{0},                    /* ctrOffs */
        0                       /* crc */
};

static int _set_fixed(char *opt, YKP_CONFIG *cfg);
static int _format_decimal_as_hex(uint8_t *dst, size_t dst_len, uint8_t *src);
static int _format_oath_id(uint8_t *dst, size_t dst_len, uint8_t vendor, uint8_t type, uint32_t mui);
static int _set_oath_id(char *opt, YKP_CONFIG *cfg, struct config_st *ycfg, YK_KEY *yk, YK_STATUS *st);

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

void report_yk_error(void)
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

/*
 * Parse all arguments supplied to this program and turn it into mainly
 * a YKP_CONFIG (but return some other parameters as well, like
 * access_code, verbose etc.).
 *
 * Done in this way to be testable (see tests/test_args_to_config.c).
 */
int args_to_config(int argc, char **argv, YKP_CONFIG *cfg, YK_KEY *yk,
		   const char **infname, const char **outfname,
		   bool *autocommit, char *salt,
		   YK_STATUS *st, bool *verbose,
		   unsigned char *access_code, bool *use_access_code,
		   bool *aesviahash, char *ndef_type, char *ndef,
		   int *exit_code)
{
	int c;
	const char *aeshash = NULL;
	bool new_access_code = false;
	bool slot_chosen = false;
	bool mode_chosen = false;
	bool option_seen = false;
	bool swap_seen = false;
	bool update_seen = false;
	bool ndef_seen = false;
	struct config_st *ycfg;

	ykp_configure_version(cfg, st);

	ycfg = (struct config_st *) ykp_core_config(cfg);

	while((c = getopt(argc, argv, optstring)) != -1) {
		if (c == 'o') {
			if (strcmp(optarg, "oath-hotp") == 0 ||
			    strcmp(optarg, "chal-resp") == 0) {
				if (mode_chosen) {
					fprintf(stderr, "You may only choose mode (-ooath-hotp / "
						"-ochal-resp) once.\n");
					*exit_code = 1;
					return 0;
				}

				if (option_seen) {
					fprintf(stderr, "Mode choosing flags (oath-hotp / chal-resp) "
						"must be set prior to any other options (-o).\n");
					*exit_code = 1;
					return 0;
				}

				/* The default flags (particularly for slot 2) does not apply to
				 * these new modes of operation found in Yubikey >= 2.1. Therefor,
				 * we reset them here and, as a consequence of that, require the
				 * mode choosing options to be specified before any other.
				 */
				ycfg->tktFlags = 0;
				ycfg->cfgFlags = 0;
				ycfg->extFlags = 0;

				mode_chosen = 1;
			}

			option_seen = true;
		}

		switch (c) {
		case 'u':
			if (slot_chosen) {
				fprintf(stderr, "You must use update before slot (-1 / -2).\n");
				*exit_code = 1;
				return 0;
			}
			if (swap_seen) {
				fprintf(stderr, "Update (-u) and swap (-x) can't be combined.\n");
				*exit_code = 1;
				return 0;
			}
			if (ndef_seen) {
				fprintf(stderr, "Update (-u) can not be combined with ndef (-n).\n");
				*exit_code = 1;
				return 0;
			}
			update_seen = true;
			break;
		case '1':
		case '2': {
				int command;
				if (slot_chosen) {
					fprintf(stderr, "You may only choose slot (-1 / -2) once.\n");
					*exit_code = 1;
					return 0;
				}
				if (option_seen) {
					fprintf(stderr, "You must choose slot before any options (-o).\n");
					*exit_code = 1;
					return 0;
				}
				if (swap_seen) {
					fprintf(stderr, "You can not combine slot swap (-x) with configuring a slot.\n");
					*exit_code = 1;
					return 0;
				}
				if (ndef_seen) {
					fprintf(stderr, "Slot (-1 / -2) can not be combined with ndef (-n)\n");
					*exit_code = 1;
					return 0;
				}
				if (update_seen) {
					memcpy(ycfg, &default_update, sizeof(default_update));
					if(c == '1') {
						command = SLOT_UPDATE1;
					} else if(c == '2') {
						command = SLOT_UPDATE2;
					}
				} else if (c == '1') {
					command = SLOT_CONFIG;
					memcpy(ycfg, &default_config1, sizeof(default_config1));
				} else if (c == '2') {
					command = SLOT_CONFIG2;
					memcpy(ycfg, &default_config2, sizeof(default_config2));
				}
				if (!ykp_configure_command(cfg, command))
					return 0;
				slot_chosen = true;
				break;
			}
		case 'x':
			if (slot_chosen) {
				fprintf(stderr, "You can not use slot swap with a chosen slot (-1 / -2).\n");
				*exit_code = 1;
				return 0;
			}
			if (option_seen) {
				fprintf(stderr, "You must set slot swap before any options (-o).\n");
				*exit_code = 1;
				return 0;
			}
			if (update_seen) {
				fprintf(stderr, "Update (-u) and swap (-x) can't be combined.\n");
				*exit_code = 1;
				return 0;
			}
			if (ndef_seen) {
				fprintf(stderr, "Swap (-x) can not be combined with ndef (-n).\n");
				*exit_code = 1;
				return 0;
			}
			if (!ykp_configure_command(cfg, SLOT_SWAP)) {
				return 0;
			}
			swap_seen = true;
			break;
		case 'i':
			*infname = optarg;
			break;
		case 's':
			*outfname = optarg;
			break;
		case 'a':
			*aesviahash = true;
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
				*exit_code = 1;
				return 0;
			}
			if (!new_access_code)
				ykp_set_access_code(cfg,
						    access_code,
						    access_code_len);
			*use_access_code = true;
			break;
		}
		case 't':
			*ndef_type = 'T';
		case 'n':
			if(!*ndef_type) {
				*ndef_type = 'U';
			}
			if (slot_chosen || swap_seen || update_seen || option_seen) {
				fprintf(stderr, "Ndef (-n/-t) must be used on it's own.\n");
				*exit_code = 1;
				return 0;
			}
			if (!ykp_configure_command(cfg, SLOT_NDEF)) {
				return 0;
			}
			memcpy(ndef, optarg, strlen(optarg));
			ndef_seen = true;
			break;
		case 'o':
			if (strncmp(optarg, "salt=", 5) == 0)
				salt = strdup(optarg+5);
			else if (strncmp(optarg, "fixed=", 6) == 0) {
				if (_set_fixed(optarg + 6, cfg) != 1) {
					fprintf(stderr,
						"Invalid fixed string: %s\n",
						optarg + 6);
					*exit_code = 1;
					return 0;
				}
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
					*exit_code = 1;
					return 0;
				}
				/* for OATH-HOTP and CHAL-RESP, uid is not applicable */
				if ((ycfg->tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP ||
				    (ycfg->tktFlags & TKTFLAG_CHAL_RESP) == TKTFLAG_CHAL_RESP) {
					fprintf(stderr,
						"Option uid= not valid with -ooath-hotp or -ochal-resp.\n"
						);
					*exit_code = 1;
					return 0;
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
					*exit_code = 1;
					return 0;
				}
				ykp_set_access_code(cfg, accbin, accbinlen);
				new_access_code = true;
			}
#define TKTFLAG(o, f)							\
			else if (strcmp(optarg, o) == 0) {		\
				if (!ykp_set_tktflag_##f(cfg, true)) {	\
					*exit_code = 1;			\
					return 0;		\
				}					\
			} else if (strcmp(optarg, "-" o) == 0) {	\
				if (! ykp_set_tktflag_##f(cfg, false)) { \
					*exit_code = 1;			\
					return 0;		\
				}					\
			}
			TKTFLAG("tab-first", TAB_FIRST)
			TKTFLAG("append-tab1", APPEND_TAB1)
			TKTFLAG("append-tab2", APPEND_TAB2)
			TKTFLAG("append-delay1", APPEND_DELAY1)
			TKTFLAG("append-delay2", APPEND_DELAY2)
			TKTFLAG("append-cr", APPEND_CR)
			TKTFLAG("protect-cfg2", PROTECT_CFG2)
			TKTFLAG("oath-hotp", OATH_HOTP)
			TKTFLAG("chal-resp", CHAL_RESP)
#undef TKTFLAG

#define CFGFLAG(o, f)							\
			else if (strcmp(optarg, o) == 0) {		\
				if (! ykp_set_cfgflag_##f(cfg, true)) {	\
					*exit_code = 1;			\
					return 0;			\
				}					\
			} else if (strcmp(optarg, "-" o) == 0) {	\
				if (! ykp_set_cfgflag_##f(cfg, false)) { \
					*exit_code = 1;			\
					return 0;			\
				}					\
			}
			CFGFLAG("send-ref", SEND_REF)
			CFGFLAG("ticket-first", TICKET_FIRST)
			CFGFLAG("pacing-10ms", PACING_10MS)
			CFGFLAG("pacing-20ms", PACING_20MS)
			CFGFLAG("allow-hidtrig", ALLOW_HIDTRIG)
			CFGFLAG("static-ticket", STATIC_TICKET)
			CFGFLAG("short-ticket", SHORT_TICKET)
			CFGFLAG("strong-pw1", STRONG_PW1)
			CFGFLAG("strong-pw2", STRONG_PW2)
			CFGFLAG("man-update", MAN_UPDATE)
			CFGFLAG("oath-hotp8", OATH_HOTP8)
			CFGFLAG("oath-fixed-modhex1", OATH_FIXED_MODHEX1)
			CFGFLAG("oath-fixed-modhex2", OATH_FIXED_MODHEX2)
			CFGFLAG("oath-fixed-modhex", OATH_FIXED_MODHEX)
			CFGFLAG("chal-yubico", CHAL_YUBICO)
			CFGFLAG("chal-hmac", CHAL_HMAC)
			CFGFLAG("hmac-lt64", HMAC_LT64)
			CFGFLAG("chal-btn-trig", CHAL_BTN_TRIG)
#undef CFGFLAG
			else if (strncmp(optarg, "oath-imf=", 9) == 0) {
				unsigned long imf;

				if (!(ycfg->tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP) {
					fprintf(stderr,
						"Option oath-imf= only valid with -ooath-hotp or -ooath-hotp8.\n"
						);
					*exit_code = 1;
					return 0;
				}

				if (sscanf(optarg+9, "%lu", &imf) != 1 ||
				    /* yubikey limitations */
				    imf > 65535*16 || imf % 16 != 0) {
					fprintf(stderr,
						"Invalid value %s for oath-imf=.\n", optarg+9
						);
					*exit_code = 1;
					return 0;
				}
				if (! ykp_set_oath_imf(cfg, imf)) {
					*exit_code = 1;
					return 0;
				}
			}
			else if (strncmp(optarg, "oath-id=", 8) == 0 || strcmp(optarg, "oath-id") == 0) {
				if (_set_oath_id(optarg, cfg, ycfg, yk, st) != 1) {
					*exit_code = 1;
					return 0;
				}
			}

#define EXTFLAG(o, f)							\
			else if (strcmp(optarg, o) == 0) {		\
				if (! ykp_set_extflag_##f(cfg, true)) {	\
					*exit_code = 1;			\
					return 0;			\
				}					\
			} else if (strcmp(optarg, "-" o) == 0) {	\
				if (! ykp_set_extflag_##f(cfg, false)) { \
					*exit_code = 1;			\
					return 0;			\
				}					\
			}
			EXTFLAG("serial-btn-visible", SERIAL_BTN_VISIBLE)
			EXTFLAG("serial-usb-visible", SERIAL_USB_VISIBLE)
			EXTFLAG("serial-api-visible", SERIAL_API_VISIBLE)
      EXTFLAG("use-numeric-keypad", USE_NUMERIC_KEYPAD)
      EXTFLAG("fast-trig", FAST_TRIG)
			EXTFLAG("allow-update", ALLOW_UPDATE)
      EXTFLAG("dormant", DORMANT)
#undef EXTFLAG
			else {
				fprintf(stderr, "Unknown option '%s'\n",
					optarg);
				fputs(usage, stderr);
				*exit_code = 1;
				return 0;
			}
			break;
		case 'v':
			*verbose = true;
			break;
		case 'y':
			*autocommit = true;
			break;
		case 'h':
		default:
			fputs(usage, stderr);
			*exit_code = 0;
			return 0;
		}
	}

	if (!slot_chosen && !ndef_seen) {
		fprintf(stderr, "A slot must be chosen with -1 or -2.\n");
		*exit_code = 1;
		return 0;
	}

	if (update_seen) {
		struct config_st *core_config = (struct config_st *) ykp_core_config(cfg);
		if ((core_config->tktFlags & TKTFLAG_UPDATE_MASK) != core_config->tktFlags) {
			fprintf(stderr, "Unallowed ticket flags with update.\n");
			*exit_code = 1;
			return 0;
		}
		if ((core_config->cfgFlags & CFGFLAG_UPDATE_MASK) != core_config->cfgFlags) {
			fprintf(stderr, "Unallowed cfg flags with update.\n");
			*exit_code = 1;
			return 0;
		}
		if ((core_config->extFlags & EXTFLAG_UPDATE_MASK) != core_config->extFlags) {
			fprintf(stderr, "Unallowed ext flags with update.\n");
			*exit_code = 1;
			return 0;
		}
	}

	if (*aesviahash) {
		bool long_key_valid = false;
		int res = 0;

		/* for OATH-HOTP, 160 bits key is also valid */
		if ((ycfg->tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP)
			long_key_valid = true;

		/* for HMAC (not Yubico) challenge-response, 160 bits key is also valid */
		if ((ycfg->tktFlags & TKTFLAG_CHAL_RESP) == TKTFLAG_CHAL_RESP &&
		    (ycfg->cfgFlags & CFGFLAG_CHAL_HMAC) == CFGFLAG_CHAL_HMAC) {
			long_key_valid = true;
		}

		if (long_key_valid && strlen(aeshash) == 40) {
			res = ykp_HMAC_key_from_hex(cfg, aeshash);
		} else {
			res = ykp_AES_key_from_hex(cfg, aeshash);
		}

		if (res) {
			fprintf(stderr, "Bad %s key: %s\n", long_key_valid ? "HMAC":"AES", aeshash);
			fflush(stderr);
			return 0;
		}
	}

	return 1;
}

static int _set_fixed(char *opt, YKP_CONFIG *cfg) {
	const char *fixed = opt;
	size_t fixedlen = strlen (fixed);
	unsigned char fixedbin[256];
	size_t fixedbinlen = 0;
	int rc = hex_modhex_decode(fixedbin, &fixedbinlen,
				   fixed, fixedlen,
				   0, 16, true);
	if (rc <= 0)
		return 0;

	ykp_set_fixed(cfg, fixedbin, fixedbinlen);
	return 1;
}


/* re-format decimal 12345678 into 'hex' 0x12 0x34 0x56 0x78 */
static int _format_decimal_as_hex(uint8_t *dst, size_t dst_len, uint8_t *src)
{
	uint8_t *end;

	end = dst + dst_len;
	while (src[0] && src[1]) {
		if (dst >= end)
			return 0;
		*dst = ((src[0] - '0') * 0x10) + src[1] - '0';
		dst++;
		src += 2;
	}

	return 1;
}

/* For details, see YubiKey Manual 2010-09-16 section 5.3.4 - OATH-HOTP Token Identifier */
static int _format_oath_id(uint8_t *dst, size_t dst_len, uint8_t vendor, uint8_t type, uint32_t mui)
{
	uint8_t buf[8 + 1];

	if (mui > 99999999)
		return 0;

	/* two bytes vendor and token type, and eight bytes MUI */
	if (dst_len < 2 + 8)
		return 0;

	/* Make the YubiKey output the MUI number in decimal */
	snprintf(buf, sizeof(buf), "%08i", mui);

	dst[0] = vendor;
	dst[1] = type;

	if (_format_decimal_as_hex(dst + 2, dst_len - 2, buf) != 1)
		return 0;

	return 1;
}

static int _set_oath_id(char *opt, YKP_CONFIG *cfg, struct config_st *ycfg, YK_KEY *yk, YK_STATUS *st) {
	/* For details, see YubiKey Manual 2010-09-16 section 5.3.4 - OATH-HOTP Token Identifier */
	if (!(ycfg->tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP) {
		fprintf(stderr,
			"Option oath-id= only valid with -ooath-hotp or -ooath-hotp8.\n"
			);
		return 0;
	}
	if (! ykp_set_cfgflag_OATH_FIXED_MODHEX2(cfg, true))
		return 0;
	if (! ykp_set_extflag_SERIAL_API_VISIBLE(cfg, true))
		return 0;

	if (strlen(opt) > 7) {
		if (_set_fixed(opt + 8, cfg) != 1) {
			fprintf(stderr,
				"Invalid OATH token identifier %s supplied with oath-id=.\n", opt + 8
				);
			return 0;
		}
	} else {
		/* No Token Id supplied, try to create one automatically based on
		 * the serial number of the YubiKey.
		 */
		unsigned int serial;
		uint8_t oath_id[12] = {0};
		if (ykds_version_major(st) > 2 ||
		    (ykds_version_major(st) == 2 &&
		     ykds_version_minor(st) >= 2)) {
			if (! yk_get_serial(yk, 0, 0, &serial)) {
				fprintf(stderr,
					"YubiKey refuses reading serial number. "
					"Can't use -ooath-id.\n"
					);
				return 0;
			}
		} else {
			fprintf(stderr,
				"YubiKey %d.%d.%d does not support reading serial number. "
				"Can't use -ooath-id.\n",
				ykds_version_major(st),
				ykds_version_minor(st),
				ykds_version_build(st)
				);
			return 0;
		}

		if (_format_oath_id(oath_id, sizeof(oath_id), YUBICO_OATH_VENDOR_ID_HEX,
				    YUBICO_HOTP_EVENT_TOKEN_TYPE, serial) != 1) {
			fprintf(stderr, "Failed formatting OATH token identifier.\n");
			return 0;
		}

		if (ykp_set_fixed(cfg, oath_id, 6) != 1) {
			fprintf(stderr,
				"Failed setting OATH token identifier.\n"
				);
			return 0;
		}
	}

	return 1;
}
