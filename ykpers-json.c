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

#include <json/json.h>
#include <string.h>


int ykp_json_export_cfg(const YKP_CONFIG *cfg, char *json, size_t len) {
	YK_CONFIG ycfg = cfg->ykcore_config;
	json_object *jobj = json_object_new_object();
	json_object *yprod_json = json_object_new_object();
	json_object *options_json = json_object_new_object();

	int mode = MODE_OTP_YUBICO;
	struct map_st *p;

	if((ycfg.cfgFlags & CFGFLAG_STATIC_TICKET) == CFGFLAG_STATIC_TICKET) {
		mode = MODE_STATIC_TICKET;
	}
	else if((ycfg.tktFlags & TKTFLAG_OATH_HOTP) == TKTFLAG_OATH_HOTP){
		if((ycfg.cfgFlags & CFGFLAG_CHAL_YUBICO) == CFGFLAG_CHAL_YUBICO) {
			mode = MODE_CHAL_YUBICO;
		} else if((ycfg.cfgFlags & CFGFLAG_CHAL_HMAC) == CFGFLAG_CHAL_HMAC) {
			mode = MODE_CHAL_HMAC;
		} else {
			mode = MODE_OATH_HOTP;
		}
	}

	for(p = modes_map; p->flag; p++) {
		if(p->flag == mode) {
			json_object *jmode = json_object_new_string(p->json_text);
			json_object_object_add(yprod_json, "mode", jmode);
			break;
		}
	}

	json_object_object_add(jobj, "yubiProdConfig", yprod_json);
	json_object_object_add(yprod_json, "options", options_json);


	if(ycfg.fixedSize != 0 && mode != MODE_STATIC_TICKET) {
		json_object *jPrefix;
		char prefix[5] = {0};

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

	for(p = ticket_flags_map; p->flag; p++) {
		if(!p->json_text) {
			continue;
		}
		if(!p->mode || (p->mode && (mode & p->mode) == mode)) {
			int set = (ycfg.tktFlags & p->flag) == p->flag;
			json_object *jsetting = json_object_new_boolean(set);
			json_object_object_add(options_json, p->json_text, jsetting);
		}
	}

	for(p = config_flags_map; p->flag; p++) {
		if(!p->json_text) {
			continue;
		}
		if(!p->mode || (p->mode && (mode & p->mode) == mode)) {
			int set = (ycfg.cfgFlags & p->flag) == p->flag;
			json_object *jsetting = json_object_new_boolean(set);
			json_object_object_add(options_json, p->json_text, jsetting);
		}
	}

	for(p = extended_flags_map; p->flag; p++) {
		if(!p->json_text) {
			continue;
		}
		if(!p->mode || (p->mode && (mode & p->mode) == mode)) {
			int set = (ycfg.extFlags & p->flag) == p->flag;
			json_object *jsetting = json_object_new_boolean(set);
			json_object_object_add(options_json, p->json_text, jsetting);
		}
	}

	strncpy(json, json_object_to_json_string(jobj), len);

	/* free the root object, will free all children */
	json_object_put(jobj);
	return 0;
}

int ykp_json_import_cfg(const char *json, size_t len, YKP_CONFIG *cfg) {
	ykp_errno = YKP_ENOTYETIMPL;
	return 0;
}

