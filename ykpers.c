/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008-2014 Yubico AB
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

#include "ykpers_lcl.h"
#include "ykpbkdf2.h"
#include "yktsd.h"
#include "ykpers-json.h"
#include "ykcore/ykbzero.h"

#include <ykpers.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <yubikey.h>

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

int ykp_clear_config(YKP_CONFIG *cfg)
{
	if(cfg) {
		cfg->ykcore_config.tktFlags = 0;
		cfg->ykcore_config.cfgFlags = 0;
		cfg->ykcore_config.extFlags = 0;
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
		if (!(cfg->yk_major_version >= 2)) {
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
	case SLOT_DEVICE_CONFIG:
		if(!(cfg->yk_major_version <= 5)) {
			ykp_errno = YKP_EYUBIKEYVER;
			return 0;
		} /* we have an intentional fall-through to the next case here */
	case SLOT_SCAN_MAP:
		if(!(cfg->yk_major_version >= 3)) {
			ykp_errno = YKP_EYUBIKEYVER;
			return 0;
		}
		break;
	case SLOT_YK4_SET_DEVICE_INFO:
		if(!(cfg->yk_major_version >= 5)) {
			ykp_errno = YKP_EYUBIKEYVER;
			return 0;
		}
		break;
	case SLOT_NDEF2:
		if(cfg->yk_major_version != 3 && cfg->yk_major_version != 5) {
			ykp_errno = YKP_EYUBIKEYVER;
			return 0;
		}
		break;
	case SLOT_NDEF:
		/* NDEF is available for neo, thus within 2.1 from build 4 */
		if (!((cfg->yk_major_version == 2 && cfg->yk_minor_version == 1 &&
			  cfg->yk_build_version >= 4) || cfg->yk_major_version == 3 || cfg->yk_major_version >= 5)) {
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
int ykp_get_supported_key_length(const YKP_CONFIG *cfg)
{
	/* OATH-HOTP and HMAC-SHA1 challenge response support 20 byte (160 bits)
	 * keys, holding the last four bytes in the uid field.
	 */
	if((ykp_get_tktflag_OATH_HOTP(cfg) &&
				!ykp_get_cfgflag_CHAL_YUBICO(cfg)) ||
			(ykp_get_tktflag_CHAL_RESP(cfg) &&
			 ykp_get_cfgflag_CHAL_HMAC(cfg))) {
		return 20;
	}

	return 16;
}

/* Decode 128 bit AES key into cfg->ykcore_config.key */
int ykp_AES_key_from_hex(YKP_CONFIG *cfg, const char *hexkey) {
	char aesbin[256] = {0};

	/* Make sure that the hexkey is exactly 32 characters */
	if (strlen(hexkey) != 32) {
		ykp_errno = YKP_EINVAL;
		return 1;  /* Bad AES key */
	}

	/* Make sure that the hexkey is made up of only [0-9a-f] */
	if (! yubikey_hex_p(hexkey)) {
		ykp_errno = YKP_EINVAL;
		return 1;
	}

	yubikey_hex_decode(aesbin, hexkey, sizeof(aesbin));
	memcpy(cfg->ykcore_config.key, aesbin, sizeof(cfg->ykcore_config.key));
	insecure_memzero (aesbin, sizeof(aesbin));

	return 0;
}

/* Store a 16 byte AES key.
 *
 * copy 16 bytes from key to cfg->ykcore_config.key
 */
int ykp_AES_key_from_raw(YKP_CONFIG *cfg, const char *key) {
	memcpy(cfg->ykcore_config.key, key, sizeof(cfg->ykcore_config.key));
	return 0;
}

/* Store a 20 byte HMAC key.
 *
 * store the first 16 bytes of key in cfg->ykcore_config.key
 * and the remaining 4 bytes in cfg->ykcore_config.uid
 */
int ykp_HMAC_key_from_raw(YKP_CONFIG *cfg, const char *key) {
	size_t size = sizeof(cfg->ykcore_config.key);
	memcpy(cfg->ykcore_config.key, key, size);
	memcpy(cfg->ykcore_config.uid, key + size, 20 - size);
	return 0;
}

/* Decode 160 bits HMAC key, used with OATH and HMAC challenge-response.
 *
 * The first 128 bits of the HMAC go key into cfg->ykcore_config.key,
 * and 32 bits into the first four bytes of cfg->ykcore_config.uid.
*/
int ykp_HMAC_key_from_hex(YKP_CONFIG *cfg, const char *hexkey) {
	char aesbin[256] = {0};
	size_t i;

	/* Make sure that the hexkey is exactly 40 characters */
	if (strlen(hexkey) != 40) {
		ykp_errno = YKP_EINVAL;
		return 1;  /* Bad HMAC key */
	}

	/* Make sure that the hexkey is made up of only [0-9a-f] */
	if (! yubikey_hex_p(hexkey)) {
		ykp_errno = YKP_EINVAL;
		return 1;
	}

	yubikey_hex_decode(aesbin, hexkey, sizeof(aesbin));
	i = sizeof(cfg->ykcore_config.key);
	memcpy(cfg->ykcore_config.key, aesbin, i);
	memcpy(cfg->ykcore_config.uid, aesbin + i, 20 - i);
	insecure_memzero (aesbin, sizeof(aesbin));

	return 0;
}

/* Generate an AES (128 bits) or HMAC (despite the function name) (160 bits)
 * key from user entered input.
 *
 * Use user provided salt, or use salt from an available random device.
 * If no random device is available we return with an error.
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
		uint8_t _salt[8] = {0};
		size_t _salt_len = 0;
		unsigned char buf[sizeof(cfg->ykcore_config.key) + 4] = {0};
		int rc;
		int key_bytes = ykp_get_supported_key_length(cfg);
		YK_PRF_METHOD prf_method = {20, yk_hmac_sha1};

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
			/* There was no randomness files, so don't do
			 * anything */
			ykp_errno = YKP_ENORANDOM;
			return 0;
		}

		rc = yk_pbkdf2(passphrase,
			       _salt, _salt_len,
			       1024,
			       buf, key_bytes,
			       &prf_method);

		if (rc) {
			memcpy(cfg->ykcore_config.key, buf, sizeof(cfg->ykcore_config.key));

			if (key_bytes == 20) {
				memcpy(cfg->ykcore_config.uid, buf + sizeof(cfg->ykcore_config.key), 4);
			}
		}

		insecure_memzero (buf, sizeof(buf));
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
	if(indx == num_identifiers) {
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

int ykp_ndef_as_text(YK_NDEF *ndef, char *text, size_t len)
{
	if(ndef->type == 'U') {
		const char *part = NULL;
		size_t offset = 0;
		if(ndef->data[0] > 0) {
			part = ndef_identifiers[ndef->data[0] - 1];
			offset = strlen(part);
		}
		if(offset + ndef->len - 1 > len) {
			ykp_errno = YKP_EINVAL;
			return 0;
		}
		if(part) {
			memcpy(text, part, offset);
		}
		memcpy(text + offset, ndef->data + 1, ndef->len - 1);
		text[ndef->len + offset] = 0;
		return 1;
	}
	else if(ndef->type == 'T') {
		unsigned char status = ndef->data[0];
		if(status & 0x80)
			status ^= 0x80;
		if(ndef->len - status - 1 > len) {
			ykp_errno = YKP_EINVAL;
			return 0;
		}
		memcpy(text, ndef->data + status + 1, ndef->len - status - 1);
		text[ndef->len - status] = 0;
		return 1;
	}
	else {
		return 0;
	}
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

YK_DEVICE_CONFIG *ykp_alloc_device_config(void)
{
	YK_DEVICE_CONFIG *cfg = malloc(sizeof(YK_DEVICE_CONFIG));
	if(cfg) {
		memset(cfg, 0, sizeof(YK_DEVICE_CONFIG));
		return cfg;
	}
	return 0;
}

int ykp_free_device_config(YK_DEVICE_CONFIG *device_config)
{
	if(device_config) {
		free(device_config);
		return 1;
	}
	return 0;
}

int ykp_set_device_mode(YK_DEVICE_CONFIG *device_config, unsigned char mode)
{
	if(device_config) {
		device_config->mode = mode;
		return 1;
	}
	ykp_errno = YKP_EINVAL;
	return 0;
}

int ykp_set_device_chalresp_timeout(YK_DEVICE_CONFIG *device_config, unsigned char timeout)
{
	if(device_config) {
		device_config->crTimeout = timeout;
		return 1;
	}
	ykp_errno = YKP_EINVAL;
	return 0;
}

int ykp_set_device_autoeject_time(YK_DEVICE_CONFIG *device_config, unsigned short eject_time)
{
	if(device_config) {
		device_config->autoEjectTime = eject_time;
		return 1;
	}
	ykp_errno = YKP_EINVAL;
	return 0;
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

static bool vcheck_v24_or_greater(const YKP_CONFIG *cfg)
{
	return (cfg->yk_major_version == 2 &&
		cfg->yk_minor_version >= 4) ||
		cfg->yk_major_version > 2;
}

static bool vcheck_v30(const YKP_CONFIG *cfg)
{
	return (cfg->yk_major_version == 3 &&
		cfg->yk_minor_version == 0);
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

bool capability_has_hidtrig(const YKP_CONFIG *cfg)
{
	return vcheck_v1(cfg);
}

bool capability_has_ticket_first(const YKP_CONFIG *cfg)
{
	return vcheck_v1(cfg);
}

bool capability_has_static(const YKP_CONFIG *cfg)
{
	return vcheck_all(cfg) && !vcheck_neo_before_5(cfg);
}

bool capability_has_static_extras(const YKP_CONFIG *cfg)
{
	return vcheck_no_v1(cfg) && !vcheck_neo_before_5(cfg);
}

bool capability_has_slot_two(const YKP_CONFIG *cfg)
{
	return vcheck_no_v1(cfg) && !vcheck_neo(cfg);
}

bool capability_has_chal_resp(const YKP_CONFIG *cfg)
{
	return vcheck_v22_or_greater(cfg);
}

bool capability_has_oath_imf(const YKP_CONFIG *cfg)
{
	return vcheck_v22_or_greater(cfg) || vcheck_neo_after_6(cfg);
}

bool capability_has_serial_api(const YKP_CONFIG *cfg)
{
	return vcheck_v22_or_greater(cfg) || vcheck_neo(cfg);
}

bool capability_has_serial(const YKP_CONFIG *cfg)
{
	return vcheck_v22_or_greater(cfg);
}

bool capability_has_oath(const YKP_CONFIG *cfg)
{
	return vcheck_v21_or_greater(cfg) || vcheck_neo(cfg);
}

bool capability_has_ticket_mods(const YKP_CONFIG *cfg)
{
	return vcheck_all(cfg);
}

bool capability_has_update(const YKP_CONFIG *cfg)
{
	return vcheck_v23_or_greater(cfg);
}

bool capability_has_fast(const YKP_CONFIG *cfg)
{
	return vcheck_v23_or_greater(cfg);
}

bool capability_has_numeric(const YKP_CONFIG *cfg)
{
	return vcheck_v23_or_greater(cfg);
}

bool capability_has_dormant(const YKP_CONFIG *cfg)
{
	return vcheck_v23_or_greater(cfg);
}

bool capability_has_led_inv(const YKP_CONFIG *cfg)
{
	return (vcheck_v24_or_greater(cfg) && !vcheck_v30(cfg));
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
} \
bool ykp_get_tktflag_ ## type(const YKP_CONFIG *cfg)		\
{								\
	if (cfg) {						\
		if((cfg->ykcore_config.tktFlags & TKTFLAG_ ## type) == TKTFLAG_ ## type)	\
			return true;				\
		else						\
			return false;				\
	}							\
	return false;						\
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
}								\
bool ykp_get_cfgflag_ ## type(const YKP_CONFIG *cfg)		\
{								\
	if (cfg) {						\
		if((cfg->ykcore_config.cfgFlags & CFGFLAG_ ## type) == CFGFLAG_ ## type)	\
			return true;				\
		else						\
			return false;				\
	}							\
	return false;						\
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
}								\
bool ykp_get_extflag_ ## type(const YKP_CONFIG *cfg)		\
{								\
	if (cfg) {						\
		if((cfg->ykcore_config.extFlags & EXTFLAG_ ## type) == EXTFLAG_ ## type)	\
			return true;				\
		else						\
			return false;				\
	}							\
	return false;						\
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
def_set_extflag(LED_INV,capability_has_led_inv)

static const char str_key_value_separator[] = ": ";
static const char str_hex_prefix[] = "h:";
static const char str_modhex_prefix[] = "m:";
static const char str_fixed[] = "fixed";
static const char str_oath_id[] = "OATH id";
static const char str_uid[] = "uid";
static const char str_key[] = "key";
static const char str_acc_code[] = "acc_code";
static const char str_oath_imf[] = "OATH IMF";

static const char str_flags_separator[] = "|";

static const char str_ticket_flags[] = "ticket_flags";
static const char str_config_flags[] = "config_flags";
static const char str_extended_flags[] = "extended_flags";


static int _ykp_legacy_export_config(const YKP_CONFIG *cfg, char *buf, size_t len) {
	if (cfg) {
		char buffer[256] = {0};
		struct map_st *p;
		unsigned char t_flags;
		bool key_bits_in_uid = false;
		YK_CONFIG ycfg = cfg->ykcore_config;
		int mode = MODE_OTP_YUBICO;

		int pos = 0;
		int written;

		if((ycfg.tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP){
			if((ycfg.cfgFlags & CFGFLAG_CHAL_HMAC) == CFGFLAG_CHAL_HMAC) {
				mode = MODE_CHAL_HMAC;
			} else if((ycfg.cfgFlags & CFGFLAG_CHAL_YUBICO) == CFGFLAG_CHAL_YUBICO) {
				mode = MODE_CHAL_YUBICO;
			} else {
				mode = MODE_OATH_HOTP;
			}
		}
		else if((ycfg.cfgFlags & CFGFLAG_STATIC_TICKET) == CFGFLAG_STATIC_TICKET) {
			mode = MODE_STATIC_TICKET;
		}

		/* for OATH-HOTP and HMAC-SHA1 challenge response, there is four bytes
		 *  additional key data in the uid field
		 */
		key_bits_in_uid = (ykp_get_supported_key_length(cfg) == 20);

		/* fixed: or OATH id: */
		if ((ycfg.tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP &&
		    ycfg.fixedSize) {
			/* First byte (vendor id) */
			if ((ycfg.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX1) == CFGFLAG_OATH_FIXED_MODHEX1 ||
			    (ycfg.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX2) == CFGFLAG_OATH_FIXED_MODHEX2 ||
			    (ycfg.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX) == CFGFLAG_OATH_FIXED_MODHEX) {
				yubikey_modhex_encode(buffer, (const char *)ycfg.fixed, 1);
			} else {
				yubikey_hex_encode(buffer, (const char *)ycfg.fixed, 1);
			}
			/* Second byte (token type) */
			if ((ycfg.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX2) == CFGFLAG_OATH_FIXED_MODHEX2 ||
			    (ycfg.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX) == CFGFLAG_OATH_FIXED_MODHEX) {
				yubikey_modhex_encode(buffer + 2, (const char *)ycfg.fixed + 1, 1);
			} else {
				yubikey_hex_encode(buffer + 2, (const char *)ycfg.fixed + 1, 1);
			}
			/* bytes 3-12 - MUI */
			if ((ycfg.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX) == CFGFLAG_OATH_FIXED_MODHEX) {
				yubikey_modhex_encode(buffer + 4, (const char *)ycfg.fixed + 2, 8);
			} else {
				yubikey_hex_encode(buffer + 4, (const char *)ycfg.fixed + 2, 8);
			}
			buffer[12] = 0;
			written = snprintf(buf, len - (size_t)pos, "%s%s%s\n", str_oath_id, str_key_value_separator, buffer);
			if (written < 0 || pos + written > len) {
				return -1;
			}
			pos += written;
		} else {
			yubikey_modhex_encode(buffer, (const char *)ycfg.fixed, ycfg.fixedSize);
			written = snprintf(buf, len - (size_t)pos, "%s%s%s%s\n", str_fixed, str_key_value_separator, str_modhex_prefix, buffer);
			if (written < 0 || pos + written > len) {
				return -1;
			}
			pos += written;
		}

		/* uid: */
		if (key_bits_in_uid) {
			strncpy(buffer, "n/a", 4);
		} else {
			yubikey_hex_encode(buffer, (const char *)ycfg.uid, UID_SIZE);
		}
		written = snprintf(buf + pos, len - (size_t)pos, "%s%s%s\n", str_uid, str_key_value_separator, buffer);
		if (written < 0 || pos + written > len) {
			return -1;
		}
		pos += written;

		/* key: */
		yubikey_hex_encode(buffer, (const char *)ycfg.key, KEY_SIZE);
		if (key_bits_in_uid) {
			yubikey_hex_encode(buffer + KEY_SIZE * 2, (const char *)ycfg.uid, 4);
		}
		written = snprintf(buf + pos, len - (size_t)pos, "%s%s%s%s\n", str_key, str_key_value_separator, str_hex_prefix, buffer);
		if (written < 0 || pos + written > len) {
			return -1;
		}
		pos += written;

		/* acc_code: */
		yubikey_hex_encode(buffer, (const char*)ycfg.accCode, ACC_CODE_SIZE);
		written = snprintf(buf + pos, len - (size_t)pos, "%s%s%s%s\n", str_acc_code, str_key_value_separator, str_hex_prefix, buffer);
		if (written < 0 || pos + written > len) {
			return -1;
		}
		pos += written;

		/* OATH IMF: */
		if ((ycfg.tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP &&
		    capability_has_oath_imf(cfg)) {
			written = snprintf(buf + pos, len - (size_t)pos, "%s%s%s%lx\n", str_oath_imf, str_key_value_separator, str_hex_prefix, ykp_get_oath_imf(cfg));
			if (written < 0 || pos + written > len) {
				return -1;
			}
			pos += written;
		}

		/* ticket_flags: */
		buffer[0] = '\0';
		for (p = _ticket_flags_map; p->flag; p++) {
			if ((ycfg.tktFlags & p->flag) == p->flag
			    && p->capability(cfg)
			    && (mode & p->mode) == mode) {
				if (*buffer) {
					strncat(buffer, str_flags_separator, 256 - strlen(buffer));
				}
				strncat(buffer, p->flag_text, 256 - strlen(buffer));
			}
		}
		written = snprintf(buf + pos, len - (size_t)pos, "%s%s%s\n", str_ticket_flags, str_key_value_separator, buffer);
		if (written < 0 || pos + written > len) {
			return -1;
		}
		pos += written;

		/* config_flags: */
		buffer[0] = '\0';
		t_flags = ycfg.cfgFlags;
		for (p = _config_flags_map; p->flag; p++) {
			if ((t_flags & p->flag) == p->flag
			    && p->capability(cfg)
			    && (mode & p->mode) == mode) {
				if (*buffer) {
					strncat(buffer, str_flags_separator, 256 - strlen(buffer));
				}
				strncat(buffer, p->flag_text, 256 - strlen(buffer));
				/* make sure we don't show more than one cfgFlag per value -
				   some cfgflags share value in different contexts
				*/
				t_flags -= p->flag;
			}
		}
		written = snprintf(buf + pos, len - (size_t)pos, "%s%s%s\n", str_config_flags, str_key_value_separator, buffer);
		if (written < 0 || pos + written > len) {
			return -1;
		}
		pos += written;

		/* extended_flags: */
		buffer[0] = '\0';
		for (p = _extended_flags_map; p->flag; p++) {
			if ((ycfg.extFlags & p->flag) == p->flag
			    && p->capability(cfg)
			    && (mode & p->mode) == mode) {
				if (*buffer) {
					strncat(buffer, str_flags_separator, 256 - strlen(buffer));
				}
				strncat(buffer, p->flag_text, 256 - strlen(buffer));
			}
		}
		written = snprintf(buf + pos, len - (size_t)pos, "%s%s%s\n", str_extended_flags, str_key_value_separator, buffer);
		if (written < 0 || pos + written > len) {
			return -1;
		}
		pos += written;

		return pos;
	}
	return 0;
}

int ykp_export_config(const YKP_CONFIG *cfg, char *buf, size_t len,
		int format) {
	if(format == YKP_FORMAT_YCFG) {
		return _ykp_json_export_cfg(cfg, buf, len);
	} else if(format == YKP_FORMAT_LEGACY) {
		return _ykp_legacy_export_config(cfg, buf, len);
	}
	ykp_errno = YKP_EINVAL;
	return 0;
}


int ykp_import_config(YKP_CONFIG *cfg, const char *buf, size_t len,
		int format) {
	if(format == YKP_FORMAT_YCFG) {
		return _ykp_json_import_cfg(cfg, buf, len);
	} else if(format == YKP_FORMAT_LEGACY) {
		ykp_errno = YKP_ENOTYETIMPL;
	} else {
		ykp_errno = YKP_EINVAL;
	}
	return 0;
}
int ykp_write_config(const YKP_CONFIG *cfg,
		     int (*writer)(const char *buf, size_t count,
				   void *userdata),
		     void *userdata) {
	if(cfg) {
		char buffer[1024] = {0};
		int ret = _ykp_legacy_export_config(cfg, buffer, 1024);
		if(ret) {
			writer(buffer, strlen(buffer), userdata);
			return 1;
		}
		return 0;
	}
	ykp_errno = YKP_ENOCFG;
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

void ykp_set_acccode_type(YKP_CONFIG *cfg, unsigned int type)
{
	cfg->ykp_acccode_type = type;
}

unsigned int ykp_get_acccode_type(const YKP_CONFIG *cfg)
{
	return cfg->ykp_acccode_type;
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
	"no randomness source available",
};
const char *ykp_strerror(int errnum)
{
	if (errnum < sizeof(errtext)/sizeof(errtext[0]))
		return errtext[errnum];
	return NULL;
}
