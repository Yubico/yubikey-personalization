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

typedef struct yubikey_st YUBIKEY;	/* Really a USB device handle. */
typedef struct status_st STATUS;	/* Status structure,
					   filled by yk_get_status(). */

typedef struct ticket_st TICKET;	/* Ticket structure... */
typedef struct config_st CONFIG;	/* Configuration structure.
					   Other libraries provide access. */
typedef struct nav_st NAV;		/* Navigation structure.
					   Other libraries provide access. */

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
extern YUBIKEY *yk_open_first_key(void);	/* opens the first key available */
extern int yk_close_key(YUBIKEY *k);		/* closes a previously opened key */

/*************************************************************************
 *
 * Functions to get data from the key.
 *
 ****/
/* fetches key status into the structure given by `status' */
extern int yk_get_status(YUBIKEY *k, STATUS *status /*, int forceUpdate */);

/*************************************************************************
 *
 * Functions to write data to the key.
 *
 ****/

/* writes the given configuration to the key.  If the configuration is NULL,
   zap the key configuration.
   acc_code has to be provided of the key has a protecting access code. */
extern int yk_write_config(YUBIKEY *k, CONFIG *cfg, unsigned char *acc_code);

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

/*=======================================================================*

/*************************************************************************
 **
 ** = = = = = = = = =   B I G   F A T   W A R N I N G   = = = = = = = = =
 **
 ** DO NOT USE THE FOLLOWING FUCTIONS DIRECTLY UNLESS YOU WRITE CORE ROUTINES!
 **
 ** These functions are declared here only to make sure they get defined
 ** correctly internally.
 **
 ** YOU HAVE BEEN WARNED!
 **
 ****/

/*************************************************************************
 *
 * Functions to send and receive data to/from the key.
 *
 ****/
extern int yk_read_from_key(YUBIKEY *k, uint8_t slot,
			    void *buf, unsigned int bufsize,
			    unsigned int *bufcount);
extern int yk_write_to_key(YUBIKEY *k, uint8_t slot,
			   const void *buf, int bufcount);

/*************************************************************************
 *
 * Internal helper functions
 *
 ****/

/* Swaps the two bytes between little and big endian on big endian machines */
extern uint16_t endian_swap_16(uint16_t x);

#endif	/* __YKCORE_H_INCLUDED__ */
