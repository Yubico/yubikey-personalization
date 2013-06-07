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

	unsigned int ykp_acccode_type;
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
	int (*setter)(YKP_CONFIG *cfg, bool state);
};

extern struct map_st _ticket_flags_map[];
extern struct map_st _config_flags_map[];
extern struct map_st _extended_flags_map[];
extern struct map_st _modes_map[];

#define MODE_CHAL_HMAC		0x01
#define MODE_OATH_HOTP		0x02
#define MODE_OTP_YUBICO		0x04
#define MODE_CHAL_YUBICO	0x08
#define MODE_STATIC_TICKET	0x10

#define MODE_CHAL_RESP		MODE_CHAL_YUBICO | MODE_CHAL_HMAC
#define MODE_OUTPUT 		MODE_STATIC_TICKET | MODE_OTP_YUBICO | MODE_OATH_HOTP
#define MODE_ALL		0xff

# ifdef __cplusplus
}
# endif

#endif /* __YKPERS_LCL_H_INCLUDED__ */
