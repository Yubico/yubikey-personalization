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

#ifndef YKPERS_ARGS_H
#define YKPERS_ARGS_H

#include "ykpers.h"

const char *usage;
const char *optstring;

int args_to_config(int argc, char **argv, YKP_CONFIG *cfg, char *oathid,
		   const char **infname, const char **outfname,
		   int *data_format, bool *autocommit,
		   YK_STATUS *st, bool *verbose, bool *dry_run,
		   char **access_code, char **new_access_code,
		   char *ndef_type, char *ndef, unsigned char *usb_mode,
		   bool *zap, unsigned char *scan_bin, unsigned char *cr_timeout,
		   unsigned short *autoeject_timeout, int *num_modes_seen,
                   unsigned char *device_info, size_t *device_info_len, int *exit_code);

int set_oath_id(char *opt, YKP_CONFIG *cfg, YK_KEY *yk, YK_STATUS *st);

void report_yk_error(void);

int hex_modhex_decode(unsigned char *result, size_t *resultlen,
    const char *str, size_t strl,
    size_t minsize, size_t maxsize,
    bool primarily_modhex);


#endif
