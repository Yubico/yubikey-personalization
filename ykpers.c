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

#include <ykpers.h>
#include <ykdef.h>
#include <ykpbkdf2.h>

#include <stdio.h>
#include <string.h>

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

			time_t t;
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

int ykp_set_access_code(CONFIG *cfg, unsigned char *access_code)
{
	if (cfg) {
		size_t max_chars = strlen(access_code);

		if (max_chars > ACC_CODE_SIZE)
			max_chars = ACC_CODE_SIZE;

		memcpy(cfg->accCode, access_code, max_chars);
		memset(cfg->accCode, 0, ACC_CODE_SIZE - max_chars);

		return 1;
	}
	return 0;
}

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
	return -1;
}
