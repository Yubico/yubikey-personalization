/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008-2014 Yubico AB
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
#include <yubikey.h> /* To get yubikey_modhex_encode and yubikey_hex_encode */
#include <ykdef.h>
#include "ykpers-args.h"

#define YUBICO_OATH_VENDOR_ID_HEX	0xe1	/* UB as hex */
#define YUBICO_HOTP_EVENT_TOKEN_TYPE	0x63	/* HE as hex */

const char *usage =
"Usage: ykpersonalize [options]\n"
"-Nkey     use nth key found\n"
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
"-z        delete the configuration in slot 1 or 2.\n"
"-sFILE    save configuration to FILE instead of key.\n"
"          (if FILE is -, send to stdout)\n"
"-iFILE    read configuration from FILE. (only valid for -fycfg)\n"
"          (if FILE is -, read from stdin)\n"
"-fformat  set the data format for -s and -i valid values are ycfg or legacy.\n"
"-a[XXX..] The AES secret key as a 32 (or 40 for OATH-HOTP/HMAC CHAL-RESP)\n"
"          char hex value (not modhex) (none to prompt for key on stdin)\n"
"          If -a is not used a random key will be generated.\n"
"-c[XXX..] A 12 char hex value (not modhex) to use as access code for programming\n"
"          (this does NOT SET the access code, that's done with -oaccess=)\n"
"          If -c is provided without argument a code is prompted for\n"
"-nXXX..   Write NDEF URI to YubiKey NEO, must be used with -1 or -2\n"
"-tXXX..   Write NDEF text to YubiKey NEO, must be used with -1 or -2\n"
"-mMODE    Set the USB device configuration of the YubiKey.\n"
"          See the manpage for details. This is for YubiKey 3 and 4 only.\n"
"-S0605..  Set the scanmap to use with the YubiKey. Must be 45 unique bytes,\n"
"          in hex.  Use with no argument to reset to the default. This is for\n"
"          YubiKey 3.0 and newer only.\n"
"-D0403..  Set the deviceinfo to use with this YubiKey. YubiKey 5 and newer only.\n"
"-oOPTION  change configuration option.  Possible OPTION arguments are:\n"
"          fixed=xxxxxxxxxxx   The public identity of key, in MODHEX.\n"
"                              This is 0-32 characters long.\n"
"          uid[=xxxxxx]        The uid part of the generated ticket, in HEX.\n"
"                              MUST be 12 characters long.\n"
"                              If argument is omitted uid is prompted for on stdin.\n"
"          access[=xxxxxx]     New access code to set, in HEX.\n"
"                              MUST be 12 characters long.\n"
"                              If argument is omitted code is prompted for on stdin.\n"
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
"          Extended flags for firmware version 2.4/3.1 and above:\n"
"          [-]led-inv             set/clear LED_INV\n"
"\n"
"-y        always commit (do not prompt)\n"
"\n"
"-d        dry-run (don't write anything to key)\n"
"\n"
"-v        verbose\n"
"-V        tool version\n"
"-h        help (this text)\n"
;
const char *optstring = ":u12xza:c:n:t:hi:o:s:f:dvym:S:VN:D:";

static int _set_fixed(char *opt, YKP_CONFIG *cfg);
static int _format_decimal_as_hex(uint8_t *dst, size_t dst_len, uint8_t *src);
static int _format_oath_id(uint8_t *dst, size_t dst_len, uint8_t vendor, uint8_t type, uint32_t mui);

int hex_modhex_decode(unsigned char *result, size_t *resultlen,
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

static int prompt_for_data(const char *prompt, char **data) {
	size_t datalen;
	fprintf(stderr, "%s", prompt);
	fflush(stderr);
	*data = calloc(257, sizeof(char));
	if(!fgets(*data, 256, stdin)) {
			fprintf(stderr, "Error reading from stdin\n");
			perror ("fgets");
			return 1;
	}
	datalen = strlen(*data);
	if(datalen > 0 && (*data)[datalen - 1] == '\n') {
			(*data)[datalen - 1] = '\0';
	}
	return 0;
}

extern char *optarg;
extern int optind;

/*
 * Parse all arguments supplied to this program and turn it into mainly
 * a YKP_CONFIG (but return some other parameters as well, like
 * access_code, verbose etc.).
 *
 * Done in this way to be testable (see tests/test_args_to_config.c).
 */
int args_to_config(int argc, char **argv, YKP_CONFIG *cfg, char *oathid,
		   size_t oathid_len, const char **infname,
		   const char **outfname, int *data_format, bool *autocommit,
		   YK_STATUS *st, bool *verbose, bool *dry_run,
		   char **access_code, char **new_access_code,
		   char *ndef_type, char *ndef, size_t ndef_len,
		   unsigned char *usb_mode, bool *zap,
		   unsigned char *scan_bin, unsigned char *cr_timeout,
		   unsigned short *autoeject_timeout, int *num_modes_seen,
			 unsigned char *device_info, size_t *device_info_len,
		   int *exit_code)
{
	int c;
	char keylocation = 0;
	const char *aeshash = NULL;
	bool slot_chosen = false;
	bool mode_chosen = false;
	bool option_seen = false;
	bool swap_seen = false;
	bool update_seen = false;
	bool ndef_seen = false;
	bool usb_mode_seen = false;
	bool scan_map_seen = false;
	bool device_info_seen = false;

	ykp_configure_version(cfg, st);

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
				ykp_clear_config(cfg);

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
				ykp_set_tktflag_APPEND_CR(cfg, true);
				if (update_seen) {
					ykp_set_extflag_ALLOW_UPDATE(cfg, true);
					if(c == '1') {
						command = SLOT_UPDATE1;
					} else if(c == '2') {
						command = SLOT_UPDATE2;
					}
				} else if (c == '1') {
					command = SLOT_CONFIG;
				} else if (c == '2') {
					command = SLOT_CONFIG2;
					ykp_set_cfgflag_STATIC_TICKET(cfg, true);
					ykp_set_cfgflag_STRONG_PW1(cfg, true);
					ykp_set_cfgflag_STRONG_PW2(cfg, true);
					ykp_set_cfgflag_MAN_UPDATE(cfg, true);

				}
				if (!ykp_configure_command(cfg, command))
					return 0;
				slot_chosen = true;
				break;
			}
		case 'x':
			if (slot_chosen || option_seen || update_seen || ndef_seen || *zap || usb_mode_seen || scan_map_seen || device_info_seen) {
				fprintf(stderr, "Slot swap (-x) can not be used with other options.\n");
				*exit_code = 1;
				return 0;
			}

			if (!ykp_configure_command(cfg, SLOT_SWAP)) {
				return 0;
			}
			swap_seen = true;
			break;
		case 'z':
			if (swap_seen || update_seen || ndef_seen || usb_mode_seen || scan_map_seen || device_info_seen) {
				fprintf(stderr, "Zap (-z) can only be used with a slot (-1 / -2).\n");
				*exit_code = 1;
				return 0;
			}
			*zap = true;
			break;
		case 'i':
			*infname = optarg;
			break;
		case 's':
			*outfname = optarg;
			break;
		case 'f':
			if(strcmp(optarg, "ycfg") == 0) {
				*data_format = YKP_FORMAT_YCFG;
			} else if(strcmp(optarg, "legacy") == 0) {
				*data_format = YKP_FORMAT_LEGACY;
			} else {
				fprintf(stderr, "The only valid formats to -f is ycfg and legacy.\n");
				*exit_code = 1;
				return 0;
			}
			break;
		case 'a':
			if(optarg[0] == '-') {
				keylocation = 2;
				optind--;
			} else {
				aeshash = optarg;
				keylocation = 1;
			}
			break;
		case 'c':
			if(optarg[0] == '-') {
				optind--;
				if(prompt_for_data(" Access code, 6 bytes (12 characters hex) : ", access_code) != 0) {
					*exit_code = 1;
					return 0;
				}
			} else {
				*access_code = strdup(optarg);
			}
			break;
		case 't':
			*ndef_type = 'T';
		case 'n': {
				  int command;
				  if(!*ndef_type) {
					  *ndef_type = 'U';
				  }
				  if (swap_seen || update_seen || option_seen || *zap || usb_mode_seen || scan_map_seen || device_info_seen) {
					  fprintf(stderr, "Ndef (-n/-t) can only be used with a slot (-1/-2).\n");
					  *exit_code = 1;
					  return 0;
				  }
				  if(ykp_command(cfg) == SLOT_CONFIG) {
					  command = SLOT_NDEF;
				  } else if(ykp_command(cfg) == SLOT_CONFIG2) {
					  command = SLOT_NDEF2;
				  } else {
					  command = SLOT_NDEF;
				  }
				  if (!ykp_configure_command(cfg, command)) {
					  return 0;
				  }
				  strncpy(ndef, optarg, ndef_len);
				  if (ndef_len > 0) {
					  ndef[ndef_len - 1] = '\0';
				  }
				  ndef_seen = true;
				  break;
			  }
		case 'm':
			if(slot_chosen || swap_seen || update_seen || option_seen || ndef_seen || *zap || scan_map_seen || device_info_seen) {
				fprintf(stderr, "USB mode (-m) can not be combined with other options.\n");
				*exit_code = 1;
				return 0;
			}
			unsigned char mode, crtime;
			unsigned short autotime;
			int matched = sscanf(optarg, "%hhx:%hhd:%hd", &mode, &crtime, &autotime);
			if(matched > 0) {
				*usb_mode = mode;
				if(matched > 1) {
					*cr_timeout = crtime;
					if(matched > 2) {
						*autoeject_timeout = autotime;
					}
				}
				usb_mode_seen = true;
				*num_modes_seen = matched;
			} else {
				fprintf(stderr, "Invalid USB operation mode.\n");
				*exit_code = 1;
				return 0;
			}
			if (!ykp_configure_command(cfg, SLOT_DEVICE_CONFIG))
				return 0;

			break;
		case 'S':
			{
				size_t scanlength = strlen(SCAN_MAP);
				if(slot_chosen || swap_seen || update_seen || option_seen || ndef_seen || *zap || usb_mode_seen || device_info_seen) {
					fprintf(stderr, "Scanmap (-S) can not be combined with other options.\n");
					*exit_code = 1;
					return 0;
				}
				{
					size_t scanbinlen;
					size_t scanlen = strlen (optarg);
					int rc = hex_modhex_decode(scan_bin, &scanbinlen,
							optarg, scanlen,
							scanlength * 2, scanlength * 2,
							false);

					if (rc <= 0) {
						fprintf(stderr,
								"Invalid scanmap string %s\n",
								optarg);
						*exit_code = 1;
						return 0;
					}
				}
				scan_map_seen = true;
			}
			if (!ykp_configure_command(cfg, SLOT_SCAN_MAP))
				return 0;
			break;
		case 'D':
			if(slot_chosen || swap_seen || update_seen || option_seen || ndef_seen || *zap || usb_mode_seen || scan_map_seen) {
				fprintf(stderr, "Deviceinfo (-D) can not be combined with other options.\n");
				*exit_code = 1;
				return 0;
			}
			{
				size_t len = strlen(optarg);
				int rc = hex_modhex_decode(device_info, device_info_len, optarg, strlen(optarg), 2, 128, false);

				if (rc <= 0) {
					fprintf(stderr, "Failed decoding deviceinfo string: '%s'\n", optarg);
					*exit_code = 1;
					return 0;
				}
				if (!ykp_configure_command(cfg, SLOT_YK4_SET_DEVICE_INFO)) {
					return 0;
				}
				device_info_seen = true;
			}
			break;
		case 'o':
			if (*zap) {
				fprintf(stderr, "No options can be given with zap (-z).\n");
				*exit_code = 1;
				return 0;
			}
			if (strncmp(optarg, "fixed=", 6) == 0) {
				if (_set_fixed(optarg + 6, cfg) != 1) {
					fprintf(stderr,
						"Invalid fixed string: %s\n",
						optarg + 6);
					*exit_code = 1;
					return 0;
				}
			}
			else if (strncmp(optarg, "uid", 3) == 0) {
				char *uid = optarg+4;
				size_t uidlen;
				unsigned char uidbin[256] = {0};
				size_t uidbinlen = 0;
				int rc;
				char *uidtmp = NULL;

				if(strncmp(optarg, "uid=", 4) != 0) {
					if(prompt_for_data(" Private ID, 6 bytes (12 characters hex) : ", &uidtmp) != 0) {
						*exit_code = 1;
						return 0;
					}
					uid = uidtmp;
				}

				uidlen = strlen(uid);
				rc = hex_modhex_decode(uidbin, &uidbinlen,
						uid, uidlen,
						12, 12, false);
				if (rc <= 0) {
					fprintf(stderr,
							"Invalid uid string: %s\n",
							uid);
					*exit_code = 1;
					return 0;
				}

				free(uidtmp);
				/* for OATH-HOTP and CHAL-RESP, uid is not applicable */
				if (ykp_get_tktflag_OATH_HOTP(cfg) || ykp_get_tktflag_CHAL_RESP(cfg)) {
					fprintf(stderr,
							"Option uid= not valid with -ooath-hotp or -ochal-resp.\n"
							);
					*exit_code = 1;
					return 0;
				}
				ykp_set_uid(cfg, uidbin, uidbinlen);
			}
			else if (strncmp(optarg, "access=", 7) == 0) {
				*new_access_code = strdup(optarg + 7);
			}
			else if (strncmp(optarg, "access", 6) == 0) {
				if(prompt_for_data(" New access code, 6 bytes (12 characters hex) : ", new_access_code) != 0) {
					*exit_code = 1;
					return 0;
				}
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

				if (!ykp_get_tktflag_OATH_HOTP(cfg)) {
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
				strncpy(oathid, optarg, oathid_len);
				if (oathid_len > 0) {
					oathid[oathid_len - 1] = '\0';
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
			EXTFLAG("led-inv", LED_INV)
#undef EXTFLAG
			else {
				fprintf(stderr, "Unknown option '%s'\n",
					optarg);
				fputs(usage, stderr);
				*exit_code = 1;
				return 0;
			}
			break;
		case 'd':
			*dry_run = true;
			break;
		case 'v':
			*verbose = true;
			break;
		case 'y':
			*autocommit = true;
			break;
		case 'V':
		case 'N':
			continue;
		case ':':
			switch(optopt) {
				case 'S':
					{
						size_t scanlength = strlen(SCAN_MAP);
						if(slot_chosen || swap_seen || update_seen || option_seen || ndef_seen || *zap || usb_mode_seen) {
							fprintf(stderr, "Scanmap (-S) can not be combined with other options.\n");
							*exit_code = 1;
							return 0;
						}
						memset(scan_bin, 0, scanlength);
						scan_map_seen = true;
						if (!ykp_configure_command(cfg, SLOT_SCAN_MAP))
							return 0;
						continue;
					}
				case 'a':
					keylocation = 2;
					continue;
				case 'c':
					if(prompt_for_data(" Access code, 6 bytes (12 characters hex) : ", access_code) != 0) {
						*exit_code = 1;
						return 0;
					}
					continue;
			}
		case 'h':
		default:
			fputs(usage, stderr);
			*exit_code = 0;
			return 0;
		}
	}

	if (!slot_chosen && !ndef_seen && !swap_seen && !usb_mode_seen && !scan_map_seen && !device_info_seen) {
		if (argc == 1) {
			fputs(usage, stderr);
		} else {
			fprintf(stderr, "A slot must be chosen with -1 or -2.\n");
		}
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

	if (! *zap && (ykp_command(cfg) == SLOT_CONFIG || ykp_command(cfg) == SLOT_CONFIG2)) {
		size_t key_bytes = (size_t)ykp_get_supported_key_length(cfg);
		int res = 0;
		char *key_tmp = NULL;
		char keybuf[20] = {0};

		if(keylocation == 2) {
			const char *prompt = " AES key, 16 bytes (32 characters hex) : ";
			if (key_bytes == 20) {
				prompt = " HMAC key, 20 bytes (40 characters hex) : ";
			}
			if (prompt_for_data(prompt, &key_tmp) != 0) {
				*exit_code = 1;
				return 0;
			}
			aeshash = key_tmp;
			keylocation = 1;
		}

		if(keylocation == 0) {
			const char *random_places[] = {
				"/dev/srandom",
				"/dev/urandom",
				"/dev/random",
				0
			};
			const char **random_place;
			size_t read_bytes = 0;

			for (random_place = random_places; *random_place; random_place++) {
				FILE *random_file = fopen(*random_place, "r");
				if (random_file) {
					read_bytes = 0;

					while (read_bytes < key_bytes) {
						size_t n = fread(&keybuf[read_bytes], 1,
								key_bytes - read_bytes, random_file);
						read_bytes += n;
					}

					fclose(random_file);
					break;
				}
			}
			if(read_bytes < key_bytes) {
				ykp_errno = YKP_ENORANDOM;
				*exit_code = 1;
				return 0;
			}
		} else {
			size_t key_len = 0;
			int rc = hex_modhex_decode((unsigned char *)keybuf, &key_len, aeshash, strlen(aeshash), key_bytes * 2, key_bytes * 2, false);

			free(key_tmp);

			if(rc <= 0) {
				fprintf(stderr, "Invalid key string\n");
				*exit_code = 1;
				return 0;
			}
		}

		if (key_bytes == 20) {
			res = ykp_HMAC_key_from_raw(cfg, keybuf);
		} else {
			res = ykp_AES_key_from_raw(cfg, keybuf);
		}

		if (res) {
			fprintf(stderr, "Bad %s key: %s\n", key_bytes == 20 ? "HMAC":"AES", aeshash);
			fflush(stderr);
			*exit_code = 1;
			return 0;
		}
	}

	return 1;
}

static int _set_fixed(char *opt, YKP_CONFIG *cfg) {
	const char *fixed = opt;
	size_t fixedlen = strlen (fixed);
	unsigned char fixedbin[256] = {0};
	size_t fixedbinlen = 0;
	int rc = hex_modhex_decode(fixedbin, &fixedbinlen,
				   fixed, fixedlen,
				   0, 32, true);
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
	uint8_t buf[8 + 1] = {0};

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

int set_oath_id(char *opt, YKP_CONFIG *cfg, YK_KEY *yk, YK_STATUS *st) {
	/* For details, see YubiKey Manual 2010-09-16 section 5.3.4 - OATH-HOTP Token Identifier */
	if (!ykp_get_tktflag_OATH_HOTP(cfg)) {
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
