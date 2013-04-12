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

#ifndef	__YKPERS_LCL_H_INCLUDED__
#define	__YKPERS_LCL_H_INCLUDED__

#include "ykcore_lcl.h"
#include "ykpers.h"

# ifdef __cplusplus
extern "C" {
# endif

struct ykp_config_t {
	unsigned int yk_major_version;
	unsigned int yk_minor_version;
	unsigned int yk_build_version;
	unsigned int command;

	YK_CONFIG ykcore_config;
};

extern bool capability_has_hidtrig(const YKP_CONFIG *cfg);
extern bool capability_has_ticket_first(const YKP_CONFIG *cfg);
extern bool capability_has_static(const YKP_CONFIG *cfg);
extern bool capability_has_static_extras(const YKP_CONFIG *cfg);
extern bool capability_has_slot_two(const YKP_CONFIG *cfg);
extern bool capability_has_chal_resp(const YKP_CONFIG *cfg);
extern bool capability_has_oath_imf(const YKP_CONFIG *cfg);
extern bool capability_has_serial_api(const YKP_CONFIG *cfg);
extern bool capability_has_serial(const YKP_CONFIG *cfg);
extern bool capability_has_oath(const YKP_CONFIG *cfg);
extern bool capability_has_ticket_mods(const YKP_CONFIG *cfg);
extern bool capability_has_update(const YKP_CONFIG *cfg);
extern bool capability_has_fast(const YKP_CONFIG *cfg);
extern bool capability_has_numeric(const YKP_CONFIG *cfg);
extern bool capability_has_dormant(const YKP_CONFIG *cfg);
extern bool capability_has_led_inv(const YKP_CONFIG *cfg);


struct map_st {
	uint8_t flag;
	const char *flag_text;
	const char *json_text;
	bool (*capability)(const YKP_CONFIG *cfg);
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
	{ TKTFLAG_TAB_FIRST,	"TAB_FIRST",	"tabFirst",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_APPEND_TAB1,	"APPEND_TAB1",	"tabBetween",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_APPEND_TAB2,	"APPEND_TAB2",	"tabLast",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_APPEND_DELAY1,"APPEND_DELAY1","appendDelay1",	capability_has_ticket_mods,	MODE_OUTPUT }, /* XXX: name? */
	{ TKTFLAG_APPEND_DELAY2,"APPEND_DELAY2","appendDelay2",	capability_has_ticket_mods,	MODE_OUTPUT }, /* XXX: name? */
	{ TKTFLAG_APPEND_CR,	"APPEND_CR",	"appendCR",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_PROTECT_CFG2,	"PROTEXT_CFG2",	"protectSecond",capability_has_slot_two,	0 },
	{ TKTFLAG_OATH_HOTP,	"OATH_HOTP",	0,		capability_has_oath,		MODE_OATH_HOTP },
	{ TKTFLAG_CHAL_RESP,	"CHAL_RESP",	0,		capability_has_chal_resp,	MODE_CHAL_RESP },
	{ 0, 0, 0, 0, 0 }
};

static struct map_st config_flags_map[] = {
	{ CFGFLAG_CHAL_YUBICO,		"CHAL_YUBICO",		0,		capability_has_chal_resp,	MODE_CHAL_YUBICO },
	{ CFGFLAG_CHAL_HMAC,		"CHAL_HMAC",		0,		capability_has_chal_resp,	MODE_CHAL_HMAC },
	{ CFGFLAG_HMAC_LT64,		"HMAC_LT64",		"hmacLT64",	capability_has_chal_resp,	MODE_CHAL_HMAC }, /* XXX: name? */
	{ CFGFLAG_CHAL_BTN_TRIG,	"CHAL_BTN_TRIG",	"buttonReqd",	capability_has_chal_resp,	MODE_CHAL_RESP },
	{ CFGFLAG_OATH_HOTP8,		"OATH_HOTP8",		0,		capability_has_oath,		MODE_OATH_HOTP },
	{ CFGFLAG_OATH_FIXED_MODHEX1,	"OATH_FIXED_MODHEX1",	0,		capability_has_oath,		MODE_OATH_HOTP },
	{ CFGFLAG_OATH_FIXED_MODHEX2,	"OATH_FIXED_MODHEX2",	0,		capability_has_oath,		MODE_OATH_HOTP },
	{ CFGFLAG_OATH_FIXED_MODHEX,	"OATH_FIXED_MODHEX",	0,		capability_has_oath,		MODE_OATH_HOTP },
	{ CFGFLAG_SEND_REF,		"SEND_REF",		"sendRef",	capability_has_ticket_mods,	MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_TICKET_FIRST,		"TICKET_FIRST",		"ticketFirst",	capability_has_ticket_mods,	MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_PACING_10MS,		"PACKING_10MS",		"pacing10MS",	capability_has_ticket_mods,	MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_PACING_20MS,		"PACING_20MS",		"pacing20MS",	capability_has_ticket_mods,	MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_ALLOW_HIDTRIG,	"ALLOW_HIDTRIG",	"allowHidtrig",	capability_has_hidtrig,		MODE_OUTPUT }, /* XXX: name? */
	{ CFGFLAG_SHORT_TICKET,		"SHORT_TICKET",		"shortTicket",	capability_has_static_extras,	MODE_STATIC_TICKET }, /* XXX: name? */
	{ CFGFLAG_STRONG_PW1,		"STRONG_PW1",		"strongPw1",	capability_has_static_extras,	MODE_STATIC_TICKET }, /* XXX: name? */
	{ CFGFLAG_STRONG_PW2,		"STRONG_PW2",		"strongPw2",	capability_has_static_extras,	MODE_STATIC_TICKET }, /* XXX: name? */
	{ CFGFLAG_MAN_UPDATE,		"MAN_UPDATE",		"manUpdate",	capability_has_static_extras,	MODE_STATIC_TICKET }, /* XXX: name? */
	{ 0, 0, 0, 0, 0 }
};

static struct map_st extended_flags_map[] = {
	{ EXTFLAG_SERIAL_BTN_VISIBLE,	"SERIAL_BTN_VISIBLE",	"serialBtnVisible",	capability_has_serial,		0 },
	{ EXTFLAG_SERIAL_USB_VISIBLE,	"SERIAL_USB_VISIBLE",	"serialUsbVisible",	capability_has_serial,		0 },
	{ EXTFLAG_SERIAL_API_VISIBLE,	"SERIAL_API_VISIBLE",	"serialApiVisible",	capability_has_serial_api,	0 },
	{ EXTFLAG_USE_NUMERIC_KEYPAD,	"USE_NUMERIC_KEYPAD",	"useNumericKeypad",	capability_has_numeric,		0 },
	{ EXTFLAG_FAST_TRIG,		"FAST_TRIG",		"fastTrig",		capability_has_fast,		0 },
	{ EXTFLAG_ALLOW_UPDATE,		"ALLOW_UPDATE",		"allowUpdate",		capability_has_update,		0 },
	{ EXTFLAG_DORMANT,		"DORMANT",		"dormant",		capability_has_dormant,		0 },
	{ EXTFLAG_LED_INV,		"LED_INV",		"ledInverted",		capability_has_led_inv,		0 },
	{ 0, 0, 0, 0, 0 }
};

static struct map_st modes_map[] = {
	{ MODE_OATH_HOTP,	0,	"oathHOTP",	0, 0 },
	{ MODE_CHAL_HMAC,	0,	"hmacCR",	0, 0 },
	{ MODE_STATIC_TICKET,	0,	"staticTicket",	0, 0 }, /* XXX: name? */
	{ MODE_CHAL_YUBICO,	0,	"yubicoCR",	0, 0 },
	{ MODE_OTP_YUBICO,	0,	"yubicoOTP",	0, 0 },
	{ 0, 0, 0, 0, 0 }
};

# ifdef __cplusplus
}
# endif

#endif /* __YKPERS_LCL_H_INCLUDED__ */
