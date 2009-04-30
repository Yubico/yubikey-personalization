/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008, 2009, Yubico AB
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

#include <ykpers.h>
#include <ykdef.h>
#include <ykpbkdf2.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

static const CONFIG default_config = {
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* fixed */
	{ 0, 0, 0, 0, 0, 0 },	/* uid */
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, /* key */
	{ 0, 0, 0, 0, 0, 0 },	/* accCode */
	0,			/* fixedSize */
	0,			/* pgmSeq */
	TKTFLAG_APPEND_CR,	/* tktFlags */
	0,			/* cfgFlags */
	0,			/* ctrOffs */
	0			/* crc */
};

CONFIG *ykp_create_config(void)
{
	CONFIG *cfg = malloc(sizeof(CONFIG));
	if (cfg) {
		memcpy(cfg, &default_config,
		       sizeof(default_config));
		return cfg;
	}
	return 0;
}

int ykp_free_config(CONFIG *cfg)
{
	if (cfg) {
		free(cfg);
		return 1;
	}
	return 0;
}

static int hex_to_binary(const char *data, char *dest)
{
	char value;
	int desti=0;
	char hexstr[3]="xx";

/* We only allow an even number of hex digits (full bytes) */
	if (strlen(data) % 2) {
		return 0;
	}

/* Convert the hex to binary. */
	while (*data != '\0' && hexstr[1] != '\0') {
		int i;
		for (i=0; i<2; i++) {
			char c;  c=tolower(*data);
			hexstr[i]=c;
			data++;
/* In ASCII, 0-9 == 48-57 and a-f == 97-102. */
			if ( (c<48||(c>57 && c<97)||c>102) && (i!=0 && c!='\0') ) {
				return 0; /* Not a valid hex digit */
			}
		}
		dest[desti] = (char)strtol(hexstr, NULL, 16);
		desti+=sizeof(char);
	}

/* Tack a NULL on the end then return the number of bytes
   in the converted binary _minus_ the NULL. */
	dest[desti] = '\0';
	return desti;
}

int ykp_AES_key_from_hex(CONFIG *cfg, const char *hexkey) {
	char aesbin[256];
	unsigned long int aeslong;

/* Make sure that the hexkey is exactly 32 characters */
	if (strlen(hexkey) != 32) {
		return 1;  /* Bad AES key */
	}

/* Make sure that the hexkey is made up of only [0-9a-f] */
	int i;
	for (i=0; i < strlen(hexkey); i++) {
		char c = tolower(hexkey[i]);
/* In ASCII, 0-9 == 48-57 and a-f == 97-102 */
		if ( c<48 || (c>57 && c<97) || c>102 ) {
			return 1;
		}
	}

	hex_to_binary(hexkey, aesbin);
	memcpy(cfg->key, aesbin, sizeof(cfg->key));

	return 0;
}

int ykp_AES_key_from_passphrase(CONFIG *cfg, const char *passphrase,
				const char *salt)
{
	if (cfg) {
		char *random_places[] = {
			"/dev/srandom",
			"/dev/urandom",
			"/dev/random",
			0
		};
		char **random_place;
		uint8_t _salt[8];
		size_t _salt_len = 0;

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
						size_t n = fread(&cfg->key[read_bytes],
								 1, KEY_SIZE - read_bytes,
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

		return yk_pbkdf2(passphrase,
				 _salt, _salt_len,
				 1024,
				 cfg->key, sizeof(cfg->key),
				 &yk_hmac_sha1);
	}
	return 0;
}

#define def_set_charfield(fnname,fieldname,size,extra)		\
int ykp_set_ ## fnname(CONFIG *cfg, unsigned char *input)	\
{								\
	if (cfg) {						\
		size_t max_chars = strlen(input);		\
								\
		if (max_chars > (size))				\
			max_chars = (size);			\
								\
		memcpy(cfg->fieldname, (input), max_chars);	\
		memset(cfg->fieldname + max_chars, 0,		\
		       (size) - max_chars);			\
		extra;						\
								\
		return 1;					\
	}							\
	ykp_errno = YKP_ENOCFG;					\
	return 0;						\
}

def_set_charfield(access_code,accCode,ACC_CODE_SIZE,)
def_set_charfield(fixed,fixed,FIXED_SIZE,cfg->fixedSize = max_chars)
def_set_charfield(uid,uid,UID_SIZE,)

#define def_set_tktflag(type)					\
int ykp_set_tktflag_ ## type(CONFIG *cfg, bool state)		\
{								\
	if (cfg) {						\
		if (state)					\
			cfg->tktFlags |= TKTFLAG_ ## type;	\
		else						\
			cfg->tktFlags &= ~TKTFLAG_ ## type;	\
		return 1;					\
	}							\
	ykp_errno = YKP_ENOCFG;					\
	return 0;						\
}

#define def_set_cfgflag(type)					\
int ykp_set_cfgflag_ ## type(CONFIG *cfg, bool state)		\
{								\
	if (cfg) {						\
		if (state)					\
			cfg->cfgFlags |= CFGFLAG_ ## type;	\
		else						\
			cfg->cfgFlags &= ~CFGFLAG_ ## type;	\
		return 1;					\
	}							\
	ykp_errno = YKP_ENOCFG;					\
	return 0;						\
}

def_set_tktflag(TAB_FIRST)
def_set_tktflag(APPEND_TAB1)
def_set_tktflag(APPEND_TAB2)
def_set_tktflag(APPEND_DELAY1)
def_set_tktflag(APPEND_DELAY2)
def_set_tktflag(APPEND_CR)

def_set_cfgflag(SEND_REF)
def_set_cfgflag(TICKET_FIRST)
def_set_cfgflag(PACING_10MS)
def_set_cfgflag(PACING_20MS)
def_set_cfgflag(ALLOW_HIDTRIG)
def_set_cfgflag(STATIC_TICKET)


const char str_key_value_separator[] = ":";
const char str_fixed[] = "fixed";
const char str_uid[] = "uid";
const char str_key[] = "key";
const char str_acc_code[] = "acc_code";

const char str_flags_separator[] = "|";

struct map_st {
	uint8_t flag;
	const char *flag_text;
};

const char str_ticket_flags[] = "ticket_flags";
struct map_st ticket_flags_map[] = {
	{ TKTFLAG_TAB_FIRST, "TAB_FIRST" },
	{ TKTFLAG_APPEND_TAB1, "APPEND_TAB1" },
	{ TKTFLAG_APPEND_TAB1, "APPEND_TAB1" },
	{ TKTFLAG_APPEND_DELAY1, "APPEND_DELAY1" },
	{ TKTFLAG_APPEND_DELAY2, "APPEND_DELAY2" },
	{ TKTFLAG_APPEND_CR, "APPEND_CR" },
	{ 0, "" }
};

const char str_config_flags[] = "config_flags";
struct map_st config_flags_map[] = {
	{ CFGFLAG_SEND_REF, "SEND_REF" },
	{ CFGFLAG_TICKET_FIRST, "TICKET_FIRST" },
	{ CFGFLAG_PACING_10MS, "PACING_10MS" },
	{ CFGFLAG_PACING_20MS, "PACING_20MS" },
	{ CFGFLAG_ALLOW_HIDTRIG, "ALLOW_HIDTRIG" },
	{ CFGFLAG_STATIC_TICKET, "STATIC_TICKET" },
	{ 0, "" }
};

int ykp_write_config(const CONFIG *cfg,
		     int (*writer)(const char *buf, size_t count,
				   void *userdata),
		     void *userdata)
{
	if (cfg) {
		char buffer[256];
		struct map_st *p;

		writer(str_fixed, strlen(str_fixed), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		yk_modhex_encode(buffer, cfg->fixed, cfg->fixedSize);
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		writer(str_uid, strlen(str_uid), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		yk_modhex_encode(buffer, cfg->uid, UID_SIZE);
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		writer(str_key, strlen(str_key), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		yk_modhex_encode(buffer, cfg->key, KEY_SIZE);
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		writer(str_acc_code, strlen(str_acc_code), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		yk_modhex_encode(buffer, cfg->accCode, ACC_CODE_SIZE);
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		buffer[0] = '\0';
		for (p = ticket_flags_map; p->flag; p++) {
			if (cfg->tktFlags & p->flag) {
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

		buffer[0] = '\0';
		for (p = config_flags_map; p->flag; p++) {
			if (cfg->cfgFlags & p->flag) {
				if (*buffer) {
					strcat(buffer, str_flags_separator);
					strcat(buffer, p->flag_text);
				} else {
					strcpy(buffer, p->flag_text);
				}
			}
		}
		writer(str_config_flags, strlen(str_config_flags), userdata);
		writer(str_key_value_separator,
		       strlen(str_key_value_separator),
		       userdata);
		writer(buffer, strlen(buffer), userdata);
		writer("\n", 1, userdata);

		return 1;
	}
	return 0;
}
int ykp_read_config(CONFIG *cfg,
		    int (*reader)(char *buf, size_t count,
				  void *userdata),
		    void *userdata)
{
	ykp_errno = YKP_ENOTYETIMPL;
	return 0;
}

/* As soon as we find a way to safely detect if we're in a threaded environment
   or not, this should be changed to support per-thread locations.  Until then,
   we only support non-threaded applications. */
static int _ykp_errno = 0;

int * const _ykp_errno_location(void)
{
	return &_ykp_errno;
}

static const char *errtext[] = {
	"",
	"not yet implemented",
	"no configuration structure given"
};
const char *ykp_strerror(int errnum)
{
	if (errnum < sizeof(errtext)/sizeof(errtext[0]))
		return errtext[errnum];
	return NULL;
}
