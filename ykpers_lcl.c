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

struct map_st _ticket_flags_map[] = {
	{ TKTFLAG_TAB_FIRST,	"TAB_FIRST",	"tabFirst",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_APPEND_TAB1,	"APPEND_TAB1",	"tabBetween",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_APPEND_TAB2,	"APPEND_TAB2",	"tabLast",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_APPEND_DELAY1,"APPEND_DELAY1","appendDelay1",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_APPEND_DELAY2,"APPEND_DELAY2","appendDelay2",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_APPEND_CR,	"APPEND_CR",	"appendCR",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ TKTFLAG_PROTECT_CFG2,	"PROTEXT_CFG2",	"protectSecond",capability_has_slot_two,	MODE_ALL },
	{ TKTFLAG_OATH_HOTP,	"OATH_HOTP",	0,		capability_has_oath,		MODE_OATH_HOTP },
	{ TKTFLAG_CHAL_RESP,	"CHAL_RESP",	0,		capability_has_chal_resp,	MODE_CHAL_RESP },
	{ 0, 0, 0, 0, 0 }
};

struct map_st _config_flags_map[] = {
	{ CFGFLAG_CHAL_YUBICO,		"CHAL_YUBICO",		0,		capability_has_chal_resp,	MODE_CHAL_YUBICO },
	{ CFGFLAG_CHAL_HMAC,		"CHAL_HMAC",		0,		capability_has_chal_resp,	MODE_CHAL_HMAC },
	{ CFGFLAG_HMAC_LT64,		"HMAC_LT64",		"hmacLt64",	capability_has_chal_resp,	MODE_CHAL_HMAC },
	{ CFGFLAG_CHAL_BTN_TRIG,	"CHAL_BTN_TRIG",	"buttonReqd",	capability_has_chal_resp,	MODE_CHAL_RESP },
	{ CFGFLAG_OATH_HOTP8,		"OATH_HOTP8",		0,		capability_has_oath,		MODE_OATH_HOTP },
	{ CFGFLAG_OATH_FIXED_MODHEX1,	"OATH_FIXED_MODHEX1",	0,		capability_has_oath,		MODE_OATH_HOTP },
	{ CFGFLAG_OATH_FIXED_MODHEX2,	"OATH_FIXED_MODHEX2",	0,		capability_has_oath,		MODE_OATH_HOTP },
	{ CFGFLAG_OATH_FIXED_MODHEX,	"OATH_FIXED_MODHEX",	0,		capability_has_oath,		MODE_OATH_HOTP },
	{ CFGFLAG_SEND_REF,		"SEND_REF",		"sendRef",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ CFGFLAG_TICKET_FIRST,		"TICKET_FIRST",		0,		capability_has_ticket_mods,	MODE_OUTPUT },
	{ CFGFLAG_PACING_10MS,		"PACKING_10MS",		"pacing10ms",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ CFGFLAG_PACING_20MS,		"PACING_20MS",		"pacing20ms",	capability_has_ticket_mods,	MODE_OUTPUT },
	{ CFGFLAG_ALLOW_HIDTRIG,	"ALLOW_HIDTRIG",	0,		capability_has_hidtrig,		MODE_OUTPUT },
	{ CFGFLAG_SHORT_TICKET,		"SHORT_TICKET",		"shortTicket",	capability_has_static_extras,	MODE_STATIC_TICKET },
	{ CFGFLAG_STRONG_PW1,		"STRONG_PW1",		"strongPw1",	capability_has_static_extras,	MODE_STATIC_TICKET },
	{ CFGFLAG_STRONG_PW2,		"STRONG_PW2",		"strongPw2",	capability_has_static_extras,	MODE_STATIC_TICKET },
	{ CFGFLAG_MAN_UPDATE,		"MAN_UPDATE",		"manUpdate",	capability_has_static_extras,	MODE_STATIC_TICKET },
	{ 0, 0, 0, 0, 0 }
};

struct map_st _extended_flags_map[] = {
	{ EXTFLAG_SERIAL_BTN_VISIBLE,	"SERIAL_BTN_VISIBLE",	"serialBtnVisible",	capability_has_serial,		MODE_ALL },
	{ EXTFLAG_SERIAL_USB_VISIBLE,	"SERIAL_USB_VISIBLE",	"serialUsbVisible",	capability_has_serial,		MODE_ALL },
	{ EXTFLAG_SERIAL_API_VISIBLE,	"SERIAL_API_VISIBLE",	"serialApiVisible",	capability_has_serial_api,	MODE_ALL },
	{ EXTFLAG_USE_NUMERIC_KEYPAD,	"USE_NUMERIC_KEYPAD",	"useNumericKeypad",	capability_has_numeric,		MODE_ALL },
	{ EXTFLAG_FAST_TRIG,		"FAST_TRIG",		"fastTrig",		capability_has_fast,		MODE_ALL },
	{ EXTFLAG_ALLOW_UPDATE,		"ALLOW_UPDATE",		"allowUpdate",		capability_has_update,		MODE_ALL },
	{ EXTFLAG_DORMANT,		"DORMANT",		"dormant",		capability_has_dormant,		MODE_ALL },
	{ EXTFLAG_LED_INV,		"LED_INV",		"ledInverted",		capability_has_led_inv,		MODE_ALL },
	{ 0, 0, 0, 0, 0 }
};


struct map_st _modes_map[] = {
	{ MODE_OATH_HOTP,	0,	"oathHOTP",	0, 0 },
	{ MODE_CHAL_HMAC,	0,	"hmacCR",	0, 0 },
	{ MODE_STATIC_TICKET,	0,	"staticTicket",	0, 0 },
	{ MODE_CHAL_YUBICO,	0,	"yubicoCR",	0, 0 },
	{ MODE_OTP_YUBICO,	0,	"yubicoOTP",	0, 0 },
	{ 0, 0, 0, 0, 0 }
};
