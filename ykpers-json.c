/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2013 Yubico AB
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
#include "ykpers-json.h"

#include <yubikey.h>

#include <json.h>
#include <string.h>

#ifdef HAVE_JSON_OBJECT_OBJECT_GET_EX
#define yk_json_object_object_get(obj, key, value) json_object_object_get_ex(obj, key, &value)
#else
typedef int json_bool;
#define yk_json_object_object_get(obj, key, value) (value = json_object_object_get(obj, key)) == NULL ? 0 : 1
#endif

static void set_json_value(struct map_st *p, int mode, json_object *options, YKP_CONFIG *cfg) {
	if(!p->json_text) {
		return;
	}
	if(p->mode && (mode & p->mode) == mode) {
		json_object *joption;
		json_bool ret = yk_json_object_object_get(options, p->json_text, joption);
		if(ret == 1 && json_object_get_type(joption) == json_type_boolean) {
			int value = json_object_get_boolean(joption);
			if(value == 1) {
				p->setter(cfg, true);
			}
		}
	}
}

int _ykp_json_export_cfg(const YKP_CONFIG *cfg, char *json, size_t len) {
	json_object *jobj = json_object_new_object();
	json_object *yprod_json = json_object_new_object();
	json_object *options_json = json_object_new_object();
	if(cfg) {
		YK_CONFIG ycfg = cfg->ykcore_config;

		int mode = MODE_OTP_YUBICO;
		struct map_st *p;
		json_object *target_config = NULL;
		json_object *prot_obj = NULL;
		int protection = ykp_get_acccode_type(cfg);

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

		for(p = _modes_map; p->flag; p++) {
			if(p->flag == mode) {
				json_object *jmode = json_object_new_string(p->json_text);
				json_object_object_add(yprod_json, "mode", jmode);
				break;
			}
		}

		if(cfg->command == SLOT_CONFIG) {
			target_config = json_object_new_int(1);
		} else if(cfg->command == SLOT_CONFIG2) {
			target_config = json_object_new_int(2);
		}
		if(target_config) {
			json_object_object_add(yprod_json, "targetConfig", target_config);
		}

		if(protection == YKP_ACCCODE_NONE) {
			prot_obj = json_object_new_string("none");
		} else if(protection == YKP_ACCCODE_RANDOM) {
			prot_obj = json_object_new_string("random");
		} else if(protection == YKP_ACCCODE_SERIAL) {
			prot_obj = json_object_new_string("id");
		}
		if(prot_obj) {
			json_object_object_add(yprod_json, "protection", prot_obj);
		}

		json_object_object_add(jobj, "yubiProdConfig", yprod_json);
		json_object_object_add(yprod_json, "options", options_json);


		if(ycfg.fixedSize != 0 && mode != MODE_STATIC_TICKET) {
			json_object *jPrefix;
			char prefix[5] = {0};

			json_object *scope;
			if(mode == MODE_OTP_YUBICO &&
					ycfg.fixed[0] == 0x00 && ycfg.fixed[1] == 0x00) {
				scope = json_object_new_string("yubiCloud");
			} else {
				scope = json_object_new_string("privatePrefix");
			}
			json_object_object_add(yprod_json, "scope", scope);

			yubikey_modhex_encode(prefix, (const char*)ycfg.fixed, 2);
			if(mode == MODE_OATH_HOTP) {
				int flag = ycfg.cfgFlags & CFGFLAG_OATH_FIXED_MODHEX;
				json_object *fixed_modhex = json_object_new_boolean(
						flag == CFGFLAG_OATH_FIXED_MODHEX ? 1 : 0);
				json_object_object_add(options_json, "fixedModhex", fixed_modhex);

				if(flag == 0) {
					yubikey_hex_encode(prefix, (const char*)ycfg.fixed, 2);
				} else if(flag == CFGFLAG_OATH_FIXED_MODHEX1) {
					yubikey_hex_encode(prefix + 2, (const char*)ycfg.fixed + 1, 1);
				}
			}
			jPrefix = json_object_new_string(prefix);
			json_object_object_add(yprod_json, "prefix", jPrefix);
		} else if(mode != MODE_STATIC_TICKET) {
			json_object *scope = json_object_new_string("noPublicId");
			json_object_object_add(yprod_json, "scope", scope);
		}

		if(mode == MODE_OATH_HOTP) {
			json_object *oathDigits;
			json_object *randomSeed;
			if((ycfg.cfgFlags & CFGFLAG_OATH_HOTP8) == CFGFLAG_OATH_HOTP8) {
				oathDigits = json_object_new_int(8);
			} else {
				oathDigits = json_object_new_int(6);
			}
			json_object_object_add(options_json, "oathDigits", oathDigits);

			if((ycfg.uid[5] == 0x01 || ycfg.uid[5] == 0x00) && ycfg.uid[4] == 0x00) {
				json_object *fixedSeedvalue = json_object_new_int(ycfg.uid[5] << 4);
				json_object_object_add(options_json, "fixedSeedvalue", fixedSeedvalue);
				randomSeed = json_object_new_boolean(0);
			} else {
				randomSeed = json_object_new_boolean(1);
			}
			json_object_object_add(options_json, "randomSeed", randomSeed);
		}

		for(p = _ticket_flags_map; p->flag; p++) {
			if(!p->json_text) {
				continue;
			}
			if(p->mode && (mode & p->mode) == mode) {
				int set = (ycfg.tktFlags & p->flag) == p->flag;
				json_object *jsetting = json_object_new_boolean(set);
				json_object_object_add(options_json, p->json_text, jsetting);
			}
		}

		for(p = _config_flags_map; p->flag; p++) {
			if(!p->json_text) {
				continue;
			}
			if(p->mode && (mode & p->mode) == mode) {
				int set = (ycfg.cfgFlags & p->flag) == p->flag;
				json_object *jsetting = json_object_new_boolean(set);
				json_object_object_add(options_json, p->json_text, jsetting);
			}
		}

		for(p = _extended_flags_map; p->flag; p++) {
			if(!p->json_text) {
				continue;
			}
			if(p->mode && (mode & p->mode) == mode) {
				int set = (ycfg.extFlags & p->flag) == p->flag;
				json_object *jsetting = json_object_new_boolean(set);
				json_object_object_add(options_json, p->json_text, jsetting);
			}
		}
	}

#ifdef HAVE_JSON_OBJECT_TO_JSON_STRING_EXT
	strncpy(json, json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY), len);
#else
	strncpy(json, json_object_to_json_string(jobj), len);
#endif
	if (len > 0) {
		json[len - 1] = '\0';
	}

	/* free the root object, will free all children */
	json_object_put(jobj);
	return strlen(json);
}

int _ykp_json_import_cfg(YKP_CONFIG *cfg, const char *json, size_t len) {
	int ret_code = 0;
	if(cfg) {
		json_object *jobj = json_tokener_parse(json);
		json_object *yprod_json, *jmode, *options, *jtarget;
		const char *raw_mode;
		int mode = MODE_OTP_YUBICO;
		struct map_st *p;
		if(!jobj) {
			ykp_errno = YKP_EINVAL;
			goto out;
		}
		if(yk_json_object_object_get(jobj, "yubiProdConfig", yprod_json) == 0) {
			ykp_errno = YKP_EINVAL;
			goto out;
		}
		if(yk_json_object_object_get(yprod_json, "mode", jmode) == 0) {
			ykp_errno = YKP_EINVAL;
			goto out;
		}
		if(yk_json_object_object_get(yprod_json, "options", options) == 0) {
			ykp_errno = YKP_EINVAL;
			goto out;
		}

		if(yk_json_object_object_get(yprod_json, "targetConfig", jtarget) == 1) {
			int target_config = json_object_get_int(jtarget);
			int command;
			if(target_config == 1) {
				command = SLOT_CONFIG;
			} else if(target_config == 2) {
				command = SLOT_CONFIG2;
			} else {
				ykp_errno = YKP_EINVAL;
				goto out;
			}
			if(ykp_command(cfg) == 0) {
				ykp_configure_command(cfg, command);
			} else if(ykp_command(cfg) != command) {
				ykp_errno = YKP_EINVAL;
				goto out;
			}
		}

		raw_mode = json_object_get_string(jmode);

		for(p = _modes_map; p->flag; p++) {
			if(strcmp(raw_mode, p->json_text) == 0) {
				mode = p->flag;
				break;
			}
		}


		if(mode == MODE_OATH_HOTP) {
			json_object *jdigits, *jrandom;
			ykp_set_tktflag_OATH_HOTP(cfg, true);
			if(yk_json_object_object_get(options, "oathDigits", jdigits) == 1) {
				int digits = json_object_get_int(jdigits);
				if(digits == 8) {
					ykp_set_cfgflag_OATH_HOTP8(cfg, true);
				}
			}
			if(yk_json_object_object_get(options, "randomSeed", jrandom) == 1) {
				int random = json_object_get_boolean(jrandom);
				int seed = 0;
				if(random == 1) {
					/* NOTE: random seed isn't implemented here for now. */
					ykp_errno = YKP_ENORANDOM;
					goto out;
				} else {
					json_object *jseed;
					if(yk_json_object_object_get(options, "fixedSeedvalue", jseed) == 1) {
						seed = json_object_get_int(jseed);
					}
				}
				ykp_set_oath_imf(cfg, (long unsigned int)seed);
			}
		} else if(mode == MODE_CHAL_HMAC) {
			ykp_set_tktflag_CHAL_RESP(cfg, true);
			ykp_set_cfgflag_CHAL_HMAC(cfg, true);
		} else if(mode == MODE_CHAL_YUBICO) {
			ykp_set_tktflag_CHAL_RESP(cfg, true);
			ykp_set_cfgflag_CHAL_YUBICO(cfg, true);
		} else if(mode == MODE_STATIC_TICKET) {
			ykp_set_cfgflag_STATIC_TICKET(cfg, true);
		}

		for(p = _ticket_flags_map; p->flag; p++) {
			set_json_value(p, mode, options, cfg);
		}

		for(p = _config_flags_map; p->flag; p++) {
			set_json_value(p, mode, options, cfg);
		}

		for(p = _extended_flags_map; p->flag; p++) {
			set_json_value(p, mode, options, cfg);
		}

		ret_code = 1;
out:
		if(jobj) {
			json_object_put(jobj);
		}
	}
	return ret_code;
}

