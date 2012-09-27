/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008-2012 Yubico AB
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

#include "ykcore_lcl.h"
#include "ykpbkdf2.h"
#include "yktsd.h"

#include <ykpers.h>

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>

#include <yubikey.h>

struct ykp_config_t {
	unsigned int yk_major_version;
	unsigned int yk_minor_version;
	unsigned int yk_build_version;
	unsigned int command;

	YK_CONFIG ykcore_config;
};

static const YK_CONFIG default_config1 = {
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* fixed */
	{ 0, 0, 0, 0, 0, 0 },	/* uid */
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* key */
	{ 0, 0, 0, 0, 0, 0 },	/* accCode */
	0,			/* fixedSize */
	0,			/* extFlags */
	TKTFLAG_APPEND_CR,	/* tktFlags */
	0,			/* cfgFlags */
	{0},			/* ctrOffs */
	0			/* crc */
};

static const YK_CONFIG default_config2 = {
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* fixed */
	{ 0, 0, 0, 0, 0, 0 },	/* uid */
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* key */
	{ 0, 0, 0, 0, 0, 0 },	/* accCode */
	0,			/* fixedSize */
	0,			/* extFlags */
	TKTFLAG_APPEND_CR,	/* tktFlags */
	/* cfgFlags */
	CFGFLAG_STATIC_TICKET | CFGFLAG_STRONG_PW1 | CFGFLAG_STRONG_PW2 | CFGFLAG_MAN_UPDATE,
	{0},			/* ctrOffs */
	0			/* crc */
};

/* From nfcforum-ts-rtd-uri-1.0.pdf */
static const char *ndef_identifiers[] = {
	"http://www.",
	"https://www.",
	"http://",
	"https://",
	"tel:",
	"mailto:",
	"ftp://anonymous:anonymous@",
	"ftp://ftp.",
	"ftps://",
	"sftp://",
	"smb://",
	"nfs://",
	"ftp://",
	"dav://",
	"news:",
	"telnet://",
	"imap:",
	"rtsp://",
	"urn:",
	"pop:",
	"sip:",
	"sips:",
	"tftp:",
	"btspp://",
	"btl2cap://",
	"btgoep://",
	"tcpobex://",
	"irdaobex://",
	"file://",
	"urn:epc:id:",
	"urn:epc:tag:",
	"urn:epc:pat:",
	"urn:epc:raw:",
	"urn:epc:",
	"urn:nfc:"
};

YKP_CONFIG *ykp_create_config(void)
{
	YKP_CONFIG *cfg = malloc(sizeof(YKP_CONFIG));
	if (cfg) {
		memcpy(&cfg->ykcore_config, &default_config1,
		       sizeof(default_config1));
		cfg->yk_major_version = 1;
		cfg->yk_minor_version = 3;
		cfg->yk_build_version = 0;
		cfg->command = SLOT_CONFIG;
		return cfg;
	}
	return 0;
}

YKP_CONFIG *ykp_alloc(void)
{
	YKP_CONFIG *cfg = malloc(sizeof(YKP_CONFIG));
	if(cfg) {
		memset(cfg, 0, sizeof(YKP_CONFIG));
		return cfg;
	}
	return 0;
}

int ykp_free_config(YKP_CONFIG *cfg)
{
	if (cfg) {
		free(cfg);
		return 1;
	}
	return 0;
}

void ykp_configure_version(YKP_CONFIG *cfg, YK_STATUS *st)
{
	cfg->yk_major_version = st->versionMajor;
	cfg->yk_minor_version = st->versionMinor;
	cfg->yk_build_version = st->versionBuild;
}

int ykp_configure_command(YKP_CONFIG *cfg, uint8_t command)
{
	switch(command) {
	case SLOT_CONFIG:
		break;
	case SLOT_CONFIG2:
		if (!cfg->yk_major_version >= 2) {
			ykp_errno = YKP_EOLDYUBIKEY;
			return 0;
		}
		/* The NEO Beta key is versioned from 2.1.4 but doesn't support slot2 */
		else if( cfg->yk_major_version == 2 && cfg->yk_minor_version == 1 &&
			  cfg->yk_build_version >= 4) {
			ykp_errno = YKP_EYUBIKEYVER;
			return 0;
		}
		break;
	case SLOT_UPDATE1:
	case SLOT_UPDATE2:
	case SLOT_SWAP:
		if (!((cfg->yk_major_version == 2 && cfg->yk_minor_version >= 3)
			  || cfg->yk_major_version > 2)) {
			ykp_errno = YKP_EOLDYUBIKEY;
			return 0;
		}
		break;
	case SLOT_NDEF:
		/* NDEF is available for neo, thus within 2.1 from build 4 */
		if (!(cfg->yk_major_version == 2 && cfg->yk_minor_version == 1 &&
			  cfg->yk_build_version >= 4)) {
			ykp_errno = YKP_EYUBIKEYVER;
			return 0;
		}
		break;
	default:
		ykp_errno = YKP_EINVCONFNUM;
		return 0;
	}
	cfg->command = command;
	return 1;
}

int ykp_configure_for(YKP_CONFIG *cfg, int confnum, YK_STATUS *st)
{
	ykp_configure_version(cfg, st);
	switch(confnum) {
	case 1:
		memcpy(&cfg->ykcore_config, &default_config1,
				sizeof(default_config1));
		return ykp_configure_command(cfg, SLOT_CONFIG);
	case 2:
		memcpy(&cfg->ykcore_config, &default_config2,
				sizeof(default_config2));
		return ykp_configure_command(cfg, SLOT_CONFIG2);
	default:
		ykp_errno = YKP_EINVCONFNUM;
		return 0;
	}
}

/* Return number of bytes of key data for this configuration.
 * 20 bytes is 160 bits, 16 bytes is 128.
 */
static int _get_supported_key_length(const YKP_CONFIG *cfg)
{
	/* OATH-HOTP and HMAC-SHA1 challenge response support 20 byte (160 bits)
	 * keys, holding the last four bytes in the uid field.
	 */
	if ((cfg->ykcore_config.tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP)
		return 20;

	if ((cfg->ykcore_config.tktFlags & TKTFLAG_CHAL_RESP) == TKTFLAG_CHAL_RESP &&
	    (cfg->ykcore_config.cfgFlags & CFGFLAG_CHAL_HMAC) == CFGFLAG_CHAL_HMAC) {
		return 20;
	}

	return 16;
}

/* Decode 128 bit AES key into cfg->ykcore_config.key */
int ykp_AES_key_from_hex(YKP_CONFIG *cfg, const char *hexkey) {
	char aesbin[256];

	/* Make sure that the hexkey is exactly 32 characters */
	if (strlen(hexkey) != 32) {
		return 1;  /* Bad AES key */
	}

	/* Make sure that the hexkey is made up of only [0-9a-f] */
	if (! yubikey_hex_p(hexkey))
		return 1;

	yubikey_hex_decode(aesbin, hexkey, sizeof(aesbin));
	memcpy(cfg->ykcore_config.key, aesbin, sizeof(cfg->ykcore_config.key));

	return 0;
}

/* Decode 160 bits HMAC key, used with OATH and HMAC challenge-response.
 *
 * The first 128 bits of the HMAC go key into cfg->ykcore_config.key,
 * and 32 bits into the first four bytes of cfg->ykcore_config.uid.
*/
int ykp_HMAC_key_from_hex(YKP_CONFIG *cfg, const char *hexkey) {
	char aesbin[256];
	size_t i;

	/* Make sure that the hexkey is exactly 40 characters */
	if (strlen(hexkey) != 40) {
		return 1;  /* Bad HMAC key */
	}

	/* Make sure that the hexkey is made up of only [0-9a-f] */
	if (! yubikey_hex_p(hexkey))
		return 1;

	yubikey_hex_decode(aesbin, hexkey, sizeof(aesbin));
	i = sizeof(cfg->ykcore_config.key);
	memcpy(cfg->ykcore_config.key, aesbin, i);
	memcpy(cfg->ykcore_config.uid, aesbin + i, 20 - i);

	return 0;
}

/* Generate an AES (128 bits) or HMAC (despite the function name) (160 bits)
 * key from user entered input.
 *
 * Use user provided salt, or use salt from an available random device.
 * If no random device is available we fall back to using 2048 bits of
 * system time data, together with the user input, as salt.
 */
int ykp_AES_key_from_passphrase(YKP_CONFIG *cfg, const char *passphrase,
				const char *salt)
{
	if (cfg) {
		const char *random_places[] = {
			"/dev/srandom",
			"/dev/urandom",
			"/dev/random",
			0
		};
		const char **random_place;
		uint8_t _salt[8];
		size_t _salt_len = 0;
		unsigned char buf[sizeof(cfg->ykcore_config.key) + 4];
		int rc;
		int key_bytes = _get_supported_key_length(cfg);

		assert (key_bytes <= sizeof(buf));

		if (salt) {
			_salt_len = strlen(salt);
			if (_salt_len > 8)
				_salt_len = 8;
			memcpy(_salt, salt, _salt_len);
		} else {
			for (random_place = random_places;
			     *random_place;
			     random_place++) {
				FILE *random_file = fopen(*random_place, "r");
				if (random_file) {
					size_t read_bytes = 0;

					while (read_bytes < sizeof(_salt)) {
						size_t n = fread(&_salt[read_bytes],
								 1, sizeof (_salt) - read_bytes,
								 random_file);
						read_bytes += n;
					}

					fclose(random_file);

					_salt_len = sizeof(_salt);

					break; /* from for loop */
				}
			}
		}
		if (_salt_len == 0) {
			/* There was no randomness files, so create a cheap
			   salt from time */
#                       include <ykpbkdf2.h>

			time_t t = time(NULL);
			uint8_t output[256]; /* 2048 bits is a lot! */

			yk_hmac_sha1.prf_fn(passphrase, strlen(passphrase),
					    (char *)&t, sizeof(t),
					    output, sizeof(output));
			memcpy(_salt, output, sizeof(_salt));
			_salt_len = sizeof(_salt);
		}

		rc = yk_pbkdf2(passphrase,
			       _salt, _salt_len,
			       1024,
			       buf, key_bytes,
			       &yk_hmac_sha1);

		if (rc) {
			memcpy(cfg->ykcore_config.key, buf, sizeof(cfg->ykcore_config.key));

			if (key_bytes == 20) {
				memcpy(cfg->ykcore_config.uid, buf + sizeof(cfg->ykcore_config.key), 4);
			}
		}

		memset (buf, 0, sizeof(buf));
		return rc;
	}
	return 0;
}

YK_NDEF *ykp_alloc_ndef(void)
{
	YK_NDEF *ndef = malloc(sizeof(YK_NDEF));
	if(ndef) {
		memset(ndef, 0, sizeof(YK_NDEF));
		return ndef;
	}
	return 0;
}

int ykp_free_ndef(YK_NDEF *ndef)
{
	if(ndef)
	{
		free(ndef);
		return 1;
	}
	return 0;
}

/* Fill in the data and len parts of the YK_NDEF struct based on supplied uri. */
int ykp_construct_ndef_uri(YK_NDEF *ndef, const char *uri)
{
	int num_identifiers = sizeof(ndef_identifiers) / sizeof(char*);
	size_t data_length;
	int indx = 0;
	for(; indx < num_identifiers; indx++) {
		size_t len = strlen(ndef_identifiers[indx]);
		if(strncmp(uri, ndef_identifiers[indx], len) == 0) {
			uri += len;
			break;
		}
	}
	data_length = strlen(uri);
	if(data_length + 1 > NDEF_DATA_SIZE) {
		ykp_errno = YKP_EINVAL;
		return 0;
	}
	if(indx > num_identifiers) {
		ndef->data[0] = 0;
	} else {
		ndef->data[0] = indx + 1;
	}
	memcpy(ndef->data + 1, uri, data_length);
	ndef->len = data_length + 1;
	ndef->type = 'U';
	return 1;
}

/* Fill in the data and len parts of the YK_NDEF struct based on supplied text. */
int ykp_construct_ndef_text(YK_NDEF *ndef, const char *text, const char *lang, bool isutf16)
{
	size_t data_length = strlen(text);
	size_t lang_length = strlen(lang);
	unsigned char status = lang_length;
	if(isutf16) {
		status &= 0x80;
	}
	if((data_length + lang_length + 1) > NDEF_DATA_SIZE) {
		ykp_errno = YKP_EINVAL;
		return 0;
	}
	ndef->data[0] = status;
	memcpy(ndef->data + 1, lang, lang_length);
	memcpy(ndef->data + lang_length + 1, text, data_length);
	ndef->len = data_length + lang_length + 1;
	ndef->type = 'T';
	return 1;
}

int ykp_set_ndef_access_code(YK_NDEF *ndef, unsigned char *access_code)
{
	if(ndef)
	{
		memcpy(ndef->curAccCode, access_code, ACC_CODE_SIZE);
		return 0;
	}
	return 1;
}

static bool vcheck_all(const YKP_CONFIG *cfg)
{
	return true;
}
static bool vcheck_v1(const YKP_CONFIG *cfg)
{
	return cfg->yk_major_version == 1;
}
static bool vcheck_no_v1(const YKP_CONFIG *cfg)
{
	return cfg->yk_major_version > 1;
}

static bool vcheck_v21_or_greater(const YKP_CONFIG *cfg)
{
	/* the NEO Beta is versioned from 2.1.4 but shouldn't be identified as a 2.1 above key */
	return (cfg->yk_major_version == 2 && cfg->yk_minor_version > 1) ||
		(cfg->yk_major_version == 2 && cfg->yk_minor_version == 1 && cfg->yk_build_version <= 3)
		|| cfg->yk_major_version > 2;
}

static bool vcheck_v22_or_greater(const YKP_CONFIG *cfg)
{
	return (cfg->yk_major_version == 2 &&
		cfg->yk_minor_version >= 2) ||
		cfg->yk_major_version > 2;
}

static bool vcheck_v23_or_greater(const YKP_CONFIG *cfg)
{
	return (cfg->yk_major_version == 2 &&
		cfg->yk_minor_version >= 3) ||
		cfg->yk_major_version > 2;
}

static bool vcheck_neo(const YKP_CONFIG *cfg)
{
	return (cfg->yk_major_version == 2 &&
			cfg->yk_minor_version == 1 &&
			cfg->yk_build_version >= 4);

}

static bool vcheck_neo_before_5(const YKP_CONFIG *cfg)
{
	return vcheck_neo(cfg) && cfg->yk_build_version < 5;
}

static bool vcheck_neo_after_6(const YKP_CONFIG *cfg)
{
	return vcheck_neo(cfg) && cfg->yk_build_version > 6;
}

static bool capability_has_hidtrig(const YKP_CONFIG *cfg)
{
	return vcheck_v1(cfg);
}

static bool capability_has_ticket_first(const YKP_CONFIG *cfg)
{
	return vcheck_v1(cfg);
}

static bool capability_has_static(const YKP_CONFIG *cfg)
{
	return vcheck_all(cfg) && !vcheck_neo_before_5(cfg);
}

static bool capability_has_static_extras(const YKP_CONFIG *cfg)
{
	return vcheck_no_v1(cfg) && !vcheck_neo_before_5(cfg);
}

static bool capability_has_slot_two(const YKP_CONFIG *cfg)
{
	return vcheck_no_v1(cfg) && !vcheck_neo(cfg);
}

static bool capability_has_chal_resp(const YKP_CONFIG *cfg)
{
	return vcheck_v22_or_greater(cfg);
}

static bool capability_has_oath_imf(const YKP_CONFIG *cfg)
{
	return vcheck_v22_or_greater(cfg) || vcheck_neo_after_6(cfg);
}

static bool capability_has_serial_api(const YKP_CONFIG *cfg)
{
	return vcheck_v22_or_greater(cfg) || vcheck_neo(cfg);
}

static bool capability_has_serial(const YKP_CONFIG *cfg)
{
	return vcheck_v22_or_greater(cfg);
}

static bool capability_has_oath(const YKP_CONFIG *cfg)
{
	return vcheck_v21_or_greater(cfg) || vcheck_neo(cfg);
}

static bool capability_has_ticket_mods(const YKP_CONFIG *cfg)
{
	return vcheck_all(cfg);
}

static bool capability_has_update(const YKP_CONFIG *cfg)
{
	return vcheck_v23_or_greater(cfg);
}

static bool capability_has_fast(const YKP_CONFIG *cfg)
{
	return vcheck_v23_or_greater(cfg);
}

static bool capability_has_numeric(const YKP_CONFIG *cfg)
{
	return vcheck_v23_or_greater(cfg);
}

static bool capability_has_dormant(const YKP_CONFIG *cfg)
{
	return vcheck_v23_or_greater(cfg);
}

int ykp_set_oath_imf(YKP_CONFIG *cfg, unsigned long imf)
{
	if (!capability_has_oath_imf(cfg)) {
		ykp_errno = YKP_EYUBIKEYVER;
		return 0;
	}
	if (imf > 65535*16) {
		ykp_errno = YKP_EINVAL;
		return 0;
	}
	if (imf % 16 != 0) {
		ykp_errno = YKP_EINVAL;
		return 0;
	}
	/* IMF/16 is 16 bits stored big-endian in uid[4] */
	imf /= 16;
	cfg->ykcore_config.uid[4] = imf >> 8;
	cfg->ykcore_config.uid[5] = imf;
	return 1;
}

unsigned long ykp_get_oath_imf(const YKP_CONFIG *cfg)
{
	if (!capability_has_oath_imf(cfg)) {
		return 0;
	}

	/* we can't do a simple cast due to alignment issues */
	return ((cfg->ykcore_config.uid[4] << 8)
		| cfg->ykcore_config.uid[5]) << 4;
}

#define def_set_charfield(fnname,fieldname,size,extra,capability)	\
int ykp_set_ ## fnname(YKP_CONFIG *cfg, unsigned char *input, size_t len)	\
{								\
	if (cfg) {						\
		size_t max_chars = len;				\
								\
		if (!capability(cfg)) {				\
			ykp_errno = YKP_EYUBIKEYVER;		\
			return 0;				\
		}						\
		if (max_chars > (size))				\
			max_chars = (size);			\
								\
		memcpy(cfg->ykcore_config.fieldname, (input), max_chars);	\
		memset(cfg->ykcore_config.fieldname + max_chars, 0,		\
		       (size) - max_chars);			\
		extra;						\
								\
		return 1;					\
	}							\
	ykp_errno = YKP_ENOCFG;					\
	return 0;						\
}

def_set_charfield(access_code,accCode,ACC_CODE_SIZE,,vcheck_all)
def_set_charfield(fixed,fixed,FIXED_SIZE,cfg->ykcore_config.fixedSize = max_chars,vcheck_all)
def_set_charfield(uid,uid,UID_SIZE,,vcheck_all)

#define def_set_tktflag(type,capability)			\
int ykp_set_tktflag_ ## type(YKP_CONFIG *cfg, bool state)	\
{								\
	if (cfg) {						\
		if (!capability(cfg)) {				\
			ykp_errno = YKP_EYUBIKEYVER;		\
			return 0;				\
		}						\
		if (state)					\
			cfg->ykcore_config.tktFlags |= TKTFLAG_ ## type;	\
		else						\
			cfg->ykcore_config.tktFlags &= ~TKTFLAG_ ## type;	\
		return 1;					\
	}							\
	ykp_errno = YKP_ENOCFG;					\
	return 0;						\
}

#define def_set_cfgflag(type,capability)			\
int ykp_set_cfgflag_ ## type(YKP_CONFIG *cfg, bool state)	\
{								\
	if (cfg) {						\
		if (!capability(cfg)) {				\
			ykp_errno = YKP_EYUBIKEYVER;		\
			return 0;				\
		}						\
		if (state)					\
			cfg->ykcore_config.cfgFlags |= CFGFLAG_ ## type;	\
		else						\
			cfg->ykcore_config.cfgFlags &= ~CFGFLAG_ ## type;	\
		return 1;					\
	}							\
	ykp_errno = YKP_ENOCFG;					\
	return 0;						\
}

#define def_set_extflag(type,capability)			\
int ykp_set_extflag_ ## type(YKP_CONFIG *cfg, bool state)	\
{								\
	if (cfg) {						\
		if (!capability(cfg)) {				\
			ykp_errno = YKP_EYUBIKEYVER;		\
			return 0;				\
		}						\
		if (state)					\
			cfg->ykcore_config.extFlags |= EXTFLAG_ ## type;	\
		else						\
			cfg->ykcore_config.extFlags &= ~EXTFLAG_ ## type;	\
		return 1;					\
	}							\
	ykp_errno = YKP_ENOCFG;					\
	return 0;						\
}

def_set_tktflag(TAB_FIRST,capability_has_ticket_mods)
def_set_tktflag(APPEND_TAB1,capability_has_ticket_mods)
def_set_tktflag(APPEND_TAB2,capability_has_ticket_mods)
def_set_tktflag(APPEND_DELAY1,capability_has_ticket_mods)
def_set_tktflag(APPEND_DELAY2,capability_has_ticket_mods)
def_set_tktflag(APPEND_CR,capability_has_ticket_mods)
def_set_tktflag(PROTECT_CFG2,capability_has_slot_two)
def_set_tktflag(OATH_HOTP,capability_has_oath)
def_set_tktflag(CHAL_RESP,capability_has_chal_resp)

def_set_cfgflag(SEND_REF,capability_has_ticket_mods)
def_set_cfgflag(TICKET_FIRST,capability_has_ticket_first)
def_set_cfgflag(PACING_10MS,capability_has_ticket_mods)
def_set_cfgflag(PACING_20MS,capability_has_ticket_mods)
def_set_cfgflag(ALLOW_HIDTRIG,capability_has_hidtrig)
def_set_cfgflag(STATIC_TICKET,capability_has_static)
def_set_cfgflag(SHORT_TICKET,capability_has_static_extras)
def_set_cfgflag(STRONG_PW1,capability_has_static_extras)
def_set_cfgflag(STRONG_PW2,capability_has_static_extras)
def_set_cfgflag(MAN_UPDATE,capability_has_static_extras)
def_set_cfgflag(OATH_HOTP8,capability_has_oath)
def_set_cfgflag(OATH_FIXED_MODHEX1,capability_has_oath)
def_set_cfgflag(OATH_FIXED_MODHEX2,capability_has_oath)
def_set_cfgflag(OATH_FIXED_MODHEX,capability_has_oath)
def_set_cfgflag(CHAL_YUBICO,capability_has_chal_resp)
def_set_cfgflag(CHAL_HMAC,capability_has_chal_resp)
def_set_cfgflag(HMAC_LT64,capability_has_chal_resp)
def_set_cfgflag(CHAL_BTN_TRIG,capability_has_chal_resp)

def_set_extflag(SERIAL_BTN_VISIBLE,capability_has_serial)
def_set_extflag(SERIAL_USB_VISIBLE,capability_has_serial)
def_set_extflag(SERIAL_API_VISIBLE,capability_has_serial_api)
def_set_extflag(USE_NUMERIC_KEYPAD,capability_has_numeric)
def_set_extflag(FAST_TRIG,capability_has_fast)
def_set_extflag(ALLOW_UPDATE,capability_has_update)
def_set_extflag(DORMANT,capability_has_dormant)

const char str_key_value_separator[] = ": ";
const char str_hex_prefix[] = "h:";
const char str_modhex_prefix[] = "m:";
const char str_fixed[] = "fixed";
const char str_oath_id[] = "OATH id";
const char str_uid[] = "uid";
const char str_key[] = "key";
const char str_acc_code[] = "acc_code";
const char str_oath_imf[] = "OATH IMF";

const char str_flags_separator[] = "|";

struct map_st {
	uint8_t flag;
	const char *flag_text;
	bool (*capability)(const YKP_CONFIG *cfg);
	unsigned char tkt_context;
};

const char str_ticket_flags[] = "ticket_flags";
struct map_st ticket_flags_map[] = {
	{ TKTFLAG_TAB_FIRST,		"TAB_FIRST",		capability_has_ticket_mods,	0 },
	{ TKTFLAG_APPEND_TAB1,		"APPEND_TAB1",		capability_has_ticket_mods,	0 },
	{ TKTFLAG_APPEND_TAB2,		"APPEND_TAB2",		capability_has_ticket_mods,	0 },
	{ TKTFLAG_APPEND_DELAY1,	"APPEND_DELAY1",	capability_has_ticket_mods,	0 },
	{ TKTFLAG_APPEND_DELAY2,	"APPEND_DELAY2",	capability_has_ticket_mods,	0 },
	{ TKTFLAG_APPEND_CR,		"APPEND_CR",		capability_has_ticket_mods,	0 },
	{ TKTFLAG_PROTECT_CFG2,		"PROTECT_CFG2",		capability_has_slot_two,	0 },
	{ TKTFLAG_OATH_HOTP,		"OATH_HOTP",		capability_has_oath,		0 },
	{ TKTFLAG_CHAL_RESP,		"CHAL_RESP",		capability_has_chal_resp,	0 },
	{ 0, "", 0 }
};

const char str_config_flags[] = "config_flags";
struct map_st config_flags_map[] = {
	/*
	  Values used to pretty-print a YKP_CONFIG in ykp_write_config().

	  The fourth field is a (tkt)context in which this (cfg)flag is valid.
	  Some cfgFlags share the same value (e.g. CFGFLAG_STRONG_PW2 and
	  CFGFLAG_OATH_FIXED_MODHEX2, both 0x40). Obvioulsy, STRONG_PW2 is not
	  in effect when we do OATH, so by setting tkt_context to TKTFLAG_OATH_HOTP
	  and having the OATH flags before STRONG_PW2 in this struct we will show
	  cfgFlag 0x40 as OATH_FIXED_MODHEX2 and not STRONG_PW2 if TKTFLAG_OATH_HOTP
	  is set.
	*/
	{ CFGFLAG_CHAL_YUBICO,		"CHAL_YUBICO",		capability_has_chal_resp,	TKTFLAG_CHAL_RESP },
	{ CFGFLAG_CHAL_HMAC,		"CHAL_HMAC",		capability_has_chal_resp,	TKTFLAG_CHAL_RESP },
	{ CFGFLAG_HMAC_LT64,		"HMAC_LT64",		capability_has_chal_resp,	TKTFLAG_CHAL_RESP },
	{ CFGFLAG_CHAL_BTN_TRIG,	"CHAL_BTN_TRIG",	capability_has_chal_resp,	TKTFLAG_CHAL_RESP },
	{ CFGFLAG_OATH_HOTP8,		"OATH_HOTP8",		capability_has_oath,		TKTFLAG_OATH_HOTP },
	{ CFGFLAG_OATH_FIXED_MODHEX1,	"OATH_FIXED_MODHEX1",	capability_has_oath,		TKTFLAG_OATH_HOTP },
	{ CFGFLAG_OATH_FIXED_MODHEX2,	"OATH_FIXED_MODHEX2",	capability_has_oath,		TKTFLAG_OATH_HOTP },
	{ CFGFLAG_OATH_FIXED_MODHEX,	"OATH_FIXED_MODHEX",	capability_has_oath,		TKTFLAG_OATH_HOTP },
	{ CFGFLAG_SEND_REF,		"SEND_REF",		capability_has_ticket_mods,	0 },
	{ CFGFLAG_TICKET_FIRST,		"TICKET_FIRST",		capability_has_ticket_first,	0 },
	{ CFGFLAG_PACING_10MS,		"PACING_10MS",		capability_has_ticket_mods,	0 },
	{ CFGFLAG_PACING_20MS,		"PACING_20MS",		capability_has_ticket_mods,	0 },
	{ CFGFLAG_ALLOW_HIDTRIG,	"ALLOW_HIDTRIG",	capability_has_hidtrig,		0 },
	{ CFGFLAG_STATIC_TICKET,	"STATIC_TICKET",	capability_has_static,		0 },
	{ CFGFLAG_SHORT_TICKET,		"SHORT_TICKET",		capability_has_static_extras,	0 },
	{ CFGFLAG_STRONG_PW1,		"STRONG_PW1",		capability_has_static_extras,	0 },
	{ CFGFLAG_STRONG_PW2,		"STRONG_PW2",		capability_has_static_extras,	0 },
	{ CFGFLAG_MAN_UPDATE,		"MAN_UPDATE",		capability_has_static_extras,	0 },
	{ 0, "" }
};

const char str_extended_flags[] = "extended_flags";
struct map_st extended_flags_map[] = {
	{ EXTFLAG_SERIAL_BTN_VISIBLE,	"SERIAL_BTN_VISIBLE",	capability_has_serial,		0 },
	{ EXTFLAG_SERIAL_USB_VISIBLE,	"SERIAL_USB_VISIBLE",	capability_has_serial ,		0 },
	{ EXTFLAG_SERIAL_API_VISIBLE,	"SERIAL_API_VISIBLE",	capability_has_serial_api,	0 },
	{ EXTFLAG_USE_NUMERIC_KEYPAD,	"USE_NUMERIC_KEYPAD",	capability_has_numeric,		0 },
	{ EXTFLAG_FAST_TRIG,		"FAST_TRIG",		capability_has_fast,		0 },
	{ EXTFLAG_ALLOW_UPDATE,		"ALLOW_UPDATE",		capability_has_update,		0 },
	{ EXTFLAG_DORMANT,		"DORMANT",		capability_has_dormant,		0 },
	{ 0, "", 0 }
};

int ykp_write_config(const YKP_CONFIG *cfg,
		     int (*writer)(const char *buf, size_t count,
				   void *userdata),
		     void *userdata)
{
	if (cfg) {
		char buffer[256];
		struct map_st *p;
		unsigned char t_flags;
		bool key_bits_in_uid = false;

		/* for OATH-HOTP and HMAC-SHA1 challenge response, there is four bytes
		 *  additional key data in the uid field
		 */
		key_bits_in_uid = (_get_supported_key_length(cfg) == 20);

		/* fixed: or OATH id: */
		if ((cfg->ykcore_config.tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP &&
		    cfg->ykcore_config.fixedSize) {
			writer(str_oath_id, strlen(str_oath_id), userdata);
			writer(str_key_value_separator,
			       strlen(str_key_value_separator),
			       userdata);
			/* First byte (vendor id) */
			if ((cfg->ykcore_config.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX1) == CFGFLAG_OATH_FIXED_MODHEX1 ||
			    (cfg->ykcore_config.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX2) == CFGFLAG_OATH_FIXED_MODHEX2 ||
			    (cfg->ykcore_config.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX) == CFGFLAG_OATH_FIXED_MODHEX) {
				yubikey_modhex_encode(buffer, (const char *)cfg->ykcore_config.fixed, 1);
			} else {
				yubikey_hex_encode(buffer, (const char *)cfg->ykcore_config.fixed, 1);
			}
			/* Second byte (token type) */
			if ((cfg->ykcore_config.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX2) == CFGFLAG_OATH_FIXED_MODHEX2 ||
			    (cfg->ykcore_config.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX) == CFGFLAG_OATH_FIXED_MODHEX) {
				yubikey_modhex_encode(buffer + 2, (const char *)cfg->ykcore_config.fixed + 1, 1);
			} else {
				yubikey_hex_encode(buffer + 2, (const char *)cfg->ykcore_config.fixed + 1, 1);
			}
			/* bytes 3-12 - MUI */
			if ((cfg->ykcore_config.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX) == CFGFLAG_OATH_FIXED_MODHEX) {
				yubikey_modhex_encode(buffer + 4, (const char *)cfg->ykcore_config.fixed + 2, 8);
			} else {
				yubikey_hex_encode(buffer + 4, (const char *)cfg->ykcore_config.fixed + 2, 8);
			}
			buffer[12] = 0;
			writer(buffer, strlen(buffer), userdata);
			writer("\n", 1, userdata);
		} else {
			writer(str_fixed, strlen(str_fixed), userdata);
			writer(str_key_value_separator,
			       strlen(str_key_value_separator),
			       userdata);
			writer(str_modhex_prefix,
			       strlen(str_modhex_prefix),
			       userdata);
			yubikey_modhex_encode(buffer, (const char *)cfg->ykcore_config.fixed, cfg->ykcore_config.fixedSize);
			writer(buffer, strlen(buffer), userdata);
			writer("\n", 1, userdata);
		}

		/* uid: */
		writer(str_uid, strlen(str_uid), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		if (key_bits_in_uid) {
			writer("n/a", 3, userdata);
		} else {
			writer(str_hex_prefix,
			       strlen(str_hex_prefix),
			       userdata);
			yubikey_hex_encode(buffer, (const char *)cfg->ykcore_config.uid, UID_SIZE);
			writer(buffer, strlen(buffer), userdata);
		}
		writer("\n", 1, userdata);

		/* key: */
		writer(str_key, strlen(str_key), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		writer(str_hex_prefix,
		       strlen(str_hex_prefix),
		       userdata);
		yubikey_hex_encode(buffer, (const char *)cfg->ykcore_config.key, KEY_SIZE);
		if (key_bits_in_uid) {
			yubikey_hex_encode(buffer + KEY_SIZE * 2, (const char *)cfg->ykcore_config.uid, 4);
		}
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		/* acc_code: */
		writer(str_acc_code, strlen(str_acc_code), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		writer(str_hex_prefix,
		       strlen(str_hex_prefix),
		       userdata);
		yubikey_hex_encode(buffer, (const char*)cfg->ykcore_config.accCode, ACC_CODE_SIZE);
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		/* OATH IMF: */
		if ((cfg->ykcore_config.tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP &&
		    capability_has_oath_imf(cfg)) {
			writer(str_oath_imf, strlen(str_oath_imf), userdata);
			writer(str_key_value_separator,
				strlen(str_key_value_separator),
				userdata);
			writer(str_hex_prefix,
				strlen(str_hex_prefix),
				userdata);
			sprintf(buffer, "%lx", ykp_get_oath_imf(cfg));
			writer(buffer, strlen(buffer), userdata);
			writer("\n", 1, userdata);
		}

		/* ticket_flags: */
		buffer[0] = '\0';
		for (p = ticket_flags_map; p->flag; p++) {
			if ((cfg->ykcore_config.tktFlags & p->flag) == p->flag
			    && p->capability(cfg)) {
				if (*buffer) {
					strcat(buffer, str_flags_separator);
					strcat(buffer, p->flag_text);
				} else {
					strcpy(buffer, p->flag_text);
				}
			}
		}
		writer(str_ticket_flags, strlen(str_ticket_flags), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		/* config_flags: */
		buffer[0] = '\0';
		t_flags = cfg->ykcore_config.cfgFlags;
		for (p = config_flags_map; p->flag; p++) {
			if ((t_flags & p->flag) == p->flag
			    && p->capability(cfg)
			    && (cfg->ykcore_config.tktFlags & p->tkt_context) == p->tkt_context) {
				if (*buffer) {
					strcat(buffer, str_flags_separator);
					strcat(buffer, p->flag_text);
				} else {
					strcpy(buffer, p->flag_text);
				}
				/* make sure we don't show more than one cfgFlag per value -
				   some cfgflags share value in different contexts
				*/
				t_flags -= p->flag;
			}
		}
		writer(str_config_flags, strlen(str_config_flags), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		/* extended_flags: */
		buffer[0] = '\0';
		for (p = extended_flags_map; p->flag; p++) {
			if ((cfg->ykcore_config.extFlags & p->flag) == p->flag
			    && p->capability(cfg)) {
				if (*buffer) {
					strcat(buffer, str_flags_separator);
					strcat(buffer, p->flag_text);
				} else {
					strcpy(buffer, p->flag_text);
				}
			}
		}
		writer(str_extended_flags, strlen(str_extended_flags), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		return 1;
	}
	return 0;
}

int ykp_read_config(YKP_CONFIG *cfg,
		    int (*reader)(char *buf, size_t count,
				  void *userdata),
		    void *userdata)
{
	ykp_errno = YKP_ENOTYETIMPL;
	return 0;
}

YK_CONFIG *ykp_core_config(YKP_CONFIG *cfg)
{
	if (cfg)
		return &cfg->ykcore_config;
	ykp_errno = YKP_ENOCFG;
	return 0;
}

int ykp_command(YKP_CONFIG *cfg) {
	if (cfg) {
		return cfg->command;
	}
	ykp_errno = YKP_ENOCFG;
	return 0;
}

int ykp_config_num(YKP_CONFIG *cfg)
{
	if (cfg) {
		if (cfg->command == SLOT_CONFIG) {
			return 1;
		} else if (cfg->command == SLOT_CONFIG2) {
			return 2;
		}
	}
	ykp_errno = YKP_ENOCFG;
	return 0;
}

int * _ykp_errno_location(void)
{
	static int tsd_init = 0;
	static int nothread_errno = 0;
	YK_DEFINE_TSD_METADATA(errno_key);
	int rc = 0;

	if (tsd_init == 0) {
		if ((rc = YK_TSD_INIT(errno_key, free)) == 0) {
			tsd_init = 1;
		} else {
			tsd_init = -1;
		}
	}

	if(YK_TSD_GET(int *, errno_key) == NULL) {
		void *p = calloc(1, sizeof(int));
		if (!p) {
			tsd_init = -1;
		} else {
			YK_TSD_SET(errno_key, p);
		}
	}
	if (tsd_init == 1) {
		return YK_TSD_GET(int *, errno_key);
	}
	return &nothread_errno;
}

static const char *errtext[] = {
	"",
	"not yet implemented",
	"no configuration structure given",
	"option not available for this Yubikey version",
	"too old yubikey for this operation",
	"invalid configuration number (this is a programming error)",
	"invalid option/argument value",
};
const char *ykp_strerror(int errnum)
{
	if (errnum < sizeof(errtext)/sizeof(errtext[0]))
		return errtext[errnum];
	return NULL;
}
