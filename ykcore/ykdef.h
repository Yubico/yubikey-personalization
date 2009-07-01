/* -*- mode:C; c-file-style: "bsd" -*- */
/*****************************************************************************************
**											**
**		Y K D E F  -  Common Yubikey project header				**
**											**
**		Date		/ Rev		/ Sign	/ Remark			**
**		06-06-03	/ 0.9.0		/ J E	/ Main				**
**		06-08-25	/ 1.0.0		/ J E	/ Rewritten for final spec	**
**		08-06-03	/ 1.3.0		/ J E	/ Added static OTP feature	**
**		09-06-02	/ 2.0.0		/ J E	/ Added version 2 flags         **
**											**
*****************************************************************************************/

#ifndef	__YKDEF_H_INCLUDED__
#define	__YKDEF_H_INCLUDED__

/* We need the structures defined here to be packed byte-wise */
#if defined(_WIN32) || defined(__GNUC__)
#pragma pack(push, 1)
#endif

/* USB Identity */

#define	YUBICO_VID				0x1050
#define	YUBIKEY_PID				0x0010

/* Slot entries */

#define	SLOT_CONFIG		1   /* First (default / V1) configuration */
#define	SLOT_NAV		2   /* V1 only */
#define SLOT_CONFIG2		3   /* Second (V2) configuration */

#define	SLOT_DATA_SIZE		64

/* Ticket structure */

#define	UID_SIZE		6	/* Size of secret ID field */

struct ticket_st {
	unsigned char uid[UID_SIZE];	/* Unique (secret) ID */
	unsigned short useCtr;		/* Use counter (incremented by 1 at first use after power up) + usage flag in msb */
	unsigned short tstpl;		/* Timestamp incremented by approx 8Hz (low part) */
	unsigned char tstph;		/* Timestamp (high part) */
	unsigned char sessionCtr;	/* Number of times used within session. 0 for first use. After it wraps from 0xff to 1 */
	unsigned short rnd;		/* Pseudo-random value */
	unsigned short crc;		/* CRC16 value of all fields */
};

/* Activation modifier of sessionUse field (bitfields not uses as they are not portable) */

#define	TICKET_ACT_HIDRPT	0x8000	/* Ticket generated at activation by keyboard (scroll/num/caps) */
#define	TICKET_CTR_MASK		0x7fff	/* Mask for useCtr value (except HID flag) */

/* Configuration structure */

#define	FIXED_SIZE		16	/* Max size of fixed field */
#define	KEY_SIZE		16	/* Size of AES key */
#define	ACC_CODE_SIZE		6	/* Size of access code to re-program device */

struct config_st {
	unsigned char fixed[FIXED_SIZE];/* Fixed data in binary format */
	unsigned char uid[UID_SIZE];	/* Fixed UID part of ticket */
	unsigned char key[KEY_SIZE];	/* AES key */
	unsigned char accCode[ACC_CODE_SIZE]; /* Access code to re-program device */
	unsigned char fixedSize;	/* Number of bytes in fixed field (0 if not used) */
	unsigned char pgmSeq;		/* Program sequence number (ignored at programming - updated by firmware) */
	unsigned char tktFlags;		/* Ticket configuration flags */
	unsigned char cfgFlags;		/* General configuration flags */
	unsigned short ctrOffs;		/* Counter offset value (ignored at programming - updated by firmware) */
	unsigned short crc;		/* CRC16 value of all fields */
};

/* Ticket flags **************************************************************/

/* Yubikey 1 and newer */
#define	TKTFLAG_TAB_FIRST	0x01	/* Send TAB before first part */
#define	TKTFLAG_APPEND_TAB1	0x02	/* Send TAB after first part */
#define	TKTFLAG_APPEND_TAB2	0x04	/* Send TAB after second part */
#define	TKTFLAG_APPEND_DELAY1	0x08	/* Add 0.5s delay after first part */
#define	TKTFLAG_APPEND_DELAY2	0x10	/* Add 0.5s delay after second part */
#define	TKTFLAG_APPEND_CR	0x20	/* Append CR as final character */

/* Yubikey 2 only */
#define TKTFLAG_PROTECT_CFG2	0x80	/* Block update of config 2 unless config 2 is configured and has this bit set */

/* Configuration flags *******************************************************/

/* Yubikey 1 and newer */
#define CFGFLAG_SEND_REF	0x01	/* Send reference string (0..F) before data */
#define CFGFLAG_PACING_10MS	0x04	/* Add 10ms intra-key pacing */
#define CFGFLAG_PACING_20MS	0x08	/* Add 20ms intra-key pacing */
#define CFGFLAG_STATIC_TICKET	0x20	/* Static ticket generation */

/* Yubikey 1 only */
#define	CFGFLAG_TICKET_FIRST	0x02	/* Send ticket first (default is fixed part) */
#define CFGFLAG_ALLOW_HIDTRIG	0x10	/* Allow trigger through HID/keyboard */

/* Yubikey 2 only */
#define CFGFLAG_SHORT_TICKET	0x02	/* Send truncated ticket (half length) */
#define CFGFLAG_STRONG_PW1	0x10	/* Strong password policy flag #1 (mixed case) */
#define CFGFLAG_STRONG_PW2	0x40	/* Strong password policy flag #2 (subtitute 0..7 to digits) */
#define CFGFLAG_MAN_UPDATE	0x80	/* Allow manual (local) update of static OTP */

/* Navigation */

/* NOTE: Navigation isn't available since Yubikey 1.3.5 and is strongly
   discouraged. */
#define	MAX_URL			48

struct nav_st {
	unsigned char scancode[MAX_URL];/* Scancode (lower 7 bits) */
	unsigned char scanmod[MAX_URL >> 2];	/* Modifier fields (packed 2 bits each) */
	unsigned char flags;		/* NAVFLAG_xxx flags */
	unsigned char filler;		/* Filler byte */
	unsigned short crc;		/* CRC16 value of all fields */
};

#define	SCANMOD_SHIFT		0x80	/* Highest bit in scancode */
#define	SCANMOD_ALT_GR		0x01	/* Lowest bit in mod */
#define	SCANMOD_WIN		0x02	/* WIN key */

/* Navigation flags */

#define	NAVFLAG_INSERT_TRIG	0x01	/* Automatic trigger when device is inserted */
#define NAVFLAG_APPEND_TKT	0x02	/* Append ticket to URL */
#define	NAVFLAG_DUAL_KEY_USAGE	0x04	/* Dual usage of key: Short = ticket  Long = Navigate */

/* Status block */

struct status_st {
	unsigned char versionMajor;	/* Firmware version information */
	unsigned char versionMinor;
	unsigned char versionBuild;
	unsigned char pgmSeq;		/* Programming sequence number. 0 if no valid configuration */
	unsigned short touchLevel;	/* Level from touch detector */
};

/* Modified hex string mapping */

#define	MODHEX_MAP		"cbdefghijklnrtuv"

#if defined(_WIN32) || defined(__GNUC__)
#pragma pack(pop)
#endif

#endif	/* __YKDEF_H_INCLUDED__ */
