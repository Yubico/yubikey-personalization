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

#ifndef	__YKCORE_H_INCLUDED__
#define	__YKCORE_H_INCLUDED__

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

/*************************************************************************
 **
 ** N O T E :  For all functions that return a value, 0 och NULL indicates
 ** an error, other values indicate success.
 **
 ************************************************************************/

/*************************************************************************
 *
 * Structures used.  They are further defined in ykdef.h
 *
 ****/

typedef struct yk_key_st YK_KEY;	/* Really a USB device handle. */
typedef struct yk_status_st YK_STATUS;	/* Status structure,
					   filled by yk_get_status(). */

typedef struct yk_ticket_st YK_TICKET;	/* Ticket structure... */
typedef struct yk_config_st YK_CONFIG;	/* Configuration structure.
					   Other libraries provide access. */
typedef struct yk_nav_st YK_NAV;	/* Navigation structure.
					   Other libraries provide access. */
typedef struct yk_frame_st YK_FRAME;	/* Data frame for write operation */

/*************************************************************************
 *
 * Library initialisation functions.
 *
 ****/
extern int yk_init(void);
extern int yk_release(void);

/*************************************************************************
 *
 * Functions to get and release the key itself.
 *
 ****/
extern YK_KEY *yk_open_first_key(void);	/* opens the first key available */
extern int yk_close_key(YK_KEY *k);		/* closes a previously opened key */

/*************************************************************************
 *
 * Functions to get data from the key.
 *
 ****/
/* fetches key status into the structure given by `status' */
extern int yk_get_status(YK_KEY *k, YK_STATUS *status /*, int forceUpdate */);
/* checks that the firmware revision of the key is supported */
extern int yk_check_firmware_version(YK_KEY *k);

/*************************************************************************
 *
 * Functions to write data to the key.
 *
 ****/

/* writes the given configuration to the key.  If the configuration is NULL,
   zap the key configuration.
   acc_code has to be provided of the key has a protecting access code. */
extern int yk_write_config(YK_KEY *k, YK_CONFIG *cfg, int confnum,
			   unsigned char *acc_code);

/*************************************************************************
 *
 * Error handling fuctions
 *
 ****/
extern int * const _yk_errno_location(void);
#define yk_errno (*_yk_errno_location())
const char *yk_strerror(int errnum);
/* The following function is only useful if yk_errno == YK_EUSBERR and
   no other USB-related operations have been performed since the time of
   error.  */
const char *yk_usb_strerror();

#define YK_EUSBERR	0x01	/* USB error reporting should be used */
#define YK_EWRONGSIZ	0x02
#define YK_EWRITEERR	0x03
#define YK_ETIMEOUT	0x04
#define YK_ENOKEY	0x05
#define YK_EFIRMWARE	0x06
#define YK_ENOMEM	0x07
#define YK_ENOSTATUS	0x07
#define YK_ENOTYETIMPL	0x08

#endif	/* __YKCORE_H_INCLUDED__ */
