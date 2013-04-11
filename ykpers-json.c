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

#include <json/json.h>
#include <string.h>

struct map_st {
	uint8_t flag;
	const char *flag_text;
	unsigned char mode;
};

#define MODE_CHAL_HMAC		0x01
#define MODE_OATH_HOTP		0x02
#define MODE_OTP_YUBICO		0x04
#define MODE_CHAL_YUBICO	0x08
#define MODE_STATIC_TICKET	0x10

#define MODE_CHAL_RESP		MODE_CHAL_YUBICO | MODE_CHAL_HMAC
#define MODE_OUTPUT 		MODE_STATIC_TICKET | MODE_OTP_YUBICO | MODE_OATH_HOTP

static struct map_st ticket_flags_map[] = {
	{ TKTFLAG_TAB_FIRST,		"tabFirst",	MODE_OUTPUT },
	{ TKTFLAG_APPEND_TAB1,		"tabBetween",	MODE_OUTPUT },
	{ TKTFLAG_APPEND_TAB2,		"tabLast",	MODE_OUTPUT },
	{ TKTFLAG_APPEND_DELAY1,	"appendDelay1",	MODE_OUTPUT }, /* XXX: name? */
	{ TKTFLAG_APPEND_DELAY2,	"appendDelay2",	MODE_OUTPUT }, /* XXX: name? */
	{ TKTFLAG_APPEND_CR,		"appendCR",	MODE_OUTPUT },
	{ TKTFLAG_PROTECT_CFG2,		"protectSecond",0 },
	{ 0, "", 0 }
};

static struct map_st config_flags_map[] = {
	{ CFGFLAG_HMAC_LT64,		"hmacLT64",	MODE_CHAL_HMAC }, /* XXX: name? */
	{ CFGFLAG_CHAL_BTN_TRIG,	"buttonReqd",	MODE_CHAL_RESP },
	{ CFGFLAG_OATH_FIXED_MODHEX1,	"oathFixedModhex1",	MODE_OATH_HOTP }, /* XXX: name? */
	{ CFGFLAG_OATH_FIXED_MODHEX2,	"oathFixedModhex2",	MODE_OATH_HOTP }, /* XXX: name? */
	{ CFGFLAG_OATH_FIXED_MODHEX,	"oathFixedModhex",	MODE_OATH_HOTP }, /* XXX: name? */
	{ CFGFLAG_SEND_REF,		"sendRef",	MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_TICKET_FIRST,		"ticketFirst",	MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_PACING_10MS,		"pacing10MS",	MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_PACING_20MS,		"pacing20MS",	MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_ALLOW_HIDTRIG,	"allowHidtrig",	MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_SHORT_TICKET,		"shortTicket",	MODE_STATIC_TICKET }, /* XXX: name? */
	{ CFGFLAG_STRONG_PW1,		"strongPw1",	MODE_STATIC_TICKET }, /* XXX: name? */
	{ CFGFLAG_STRONG_PW2,		"strongPw2",	MODE_STATIC_TICKET }, /* XXX: name? */
	{ CFGFLAG_MAN_UPDATE,		"manUpdate",	MODE_STATIC_TICKET }, /* XXX: name? */
	{ 0, "", 0 }
};

static struct map_st extended_flags_map[] = {
	{ EXTFLAG_SERIAL_BTN_VISIBLE,	"serialBtnVisible",	0 },
	{ EXTFLAG_SERIAL_USB_VISIBLE,	"serialUsbVisible",	0 },
	{ EXTFLAG_SERIAL_API_VISIBLE,	"serialApiVisible",	0 },
	{ EXTFLAG_USE_NUMERIC_KEYPAD,	"useNumericKeypad",	0 },
	{ EXTFLAG_FAST_TRIG,		"fastTrig",		0 },
	{ EXTFLAG_ALLOW_UPDATE,		"allowUpdate",		0 },
	{ EXTFLAG_DORMANT,		"dormant",		0 },
	{ EXTFLAG_LED_INV,		"invertLed",		0 }, /* XXX: name? */
	{ 0, "", 0 }
};

static struct map_st modes_map[] = {
	{ MODE_OATH_HOTP,	"oathHOTP",	0 },
	{ MODE_CHAL_HMAC,	"hmacCR",	0 },
	{ MODE_STATIC_TICKET,	"staticTicket",	0 }, /* XXX: name? */
	{ MODE_CHAL_YUBICO,	"yubicoCR",	0 }, /* XXX: name? */
	{ MODE_OTP_YUBICO,	"yubicoOTP",	0 },
	{ 0, "", 0 }
};

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
			json_object *jmode = json_object_new_string(p->flag_text);
			json_object_object_add(yprod_json, "mode", jmode);
		}
	}

	json_object_object_add(jobj, "yubiProdConfig", yprod_json);
	json_object_object_add(yprod_json, "options", options_json);

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
		if(!p->mode || (p->mode && (mode & p->mode) == mode)) {
			int set = (ycfg.tktFlags & p->flag) == p->flag;
			json_object *jsetting = json_object_new_boolean(set);
			json_object_object_add(options_json, p->flag_text, jsetting);
		}
	}

	for(p = config_flags_map; p->flag; p++) {
		if(!p->mode || (p->mode && (mode & p->mode) == mode)) {
			int set = (ycfg.cfgFlags & p->flag) == p->flag;
			json_object *jsetting = json_object_new_boolean(set);
			json_object_object_add(options_json, p->flag_text, jsetting);
		}
	}

	for(p = extended_flags_map; p->flag; p++) {
		int set = (ycfg.extFlags & p->flag) == p->flag;
		json_object *jsetting = json_object_new_boolean(set);
		json_object_object_add(options_json, p->flag_text, jsetting);
	}

	strncpy(json, json_object_to_json_string(jobj), len);

	/* free the root object, will free all children */
	json_object_put(jobj);
	return 0;
}

int ykp_json_import_cfg(const char *json, size_t len, YKP_CONFIG *cfg) {
	return 0;
}

