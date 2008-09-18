/*****************************************************************************************
**											**
**		Y K D E F  -  Common Yubikey project header				**
**											**
**		Date		/ Rev		/ Sign	/ Remark			**
**		06-06-03	/ 0.9.0		/ J E	/ Main				**
**		06-08-25	/ 1.0.0		/ J E	/ Rewritten for final spec	**
**		08-06-03	/ 1.3.0		/ J E	/ Added static OTP feature	**
**											**
*****************************************************************************************/

#ifndef	__YKDEF_H_INCLUDED__
#define	__YKDEF_H_INCLUDED__

// Slot entries

#define	SLOT_CONFIG		1
#define	SLOT_NAV		2

#define	SLOT_DATA_SIZE		64

// Ticket structure

#define	UID_SIZE		6	// Size of secret ID field

typedef struct {
	unsigned char uid[UID_SIZE];	// Unique (secret) ID
	unsigned short useCtr;		// Use counter (incremented by 1 at first use after power up) + usage flag in msb
	unsigned short tstpl;		// Timestamp incremented by approx 8Hz (low part)
	unsigned char tstph;		// Timestamp (high part)
	unsigned char sessionCtr;	// Number of times used within session. 0 for first use. After it wraps from 0xff to 1
	unsigned short rnd;		// Pseudo-random value
	unsigned short crc;		// CRC16 value of all fields
} TICKET;

// Activation modifier of sessionUse field (bitfields not uses as they are not portable)

#define	TICKET_ACT_HIDRPT	0x8000	// Ticket generated at activation by keyboard (scroll/num/caps)
#define	TICKET_CTR_MASK		0x7fff	// Mask for useCtr value (except HID flag)

// Configuration structure

#define	FIXED_SIZE		16	// Max size of fixed field
#define	KEY_SIZE		16	// Size of AES key
#define	ACC_CODE_SIZE		6	// Size of access code to re-program device

typedef struct {
	unsigned char fixed[FIXED_SIZE];// Fixed data in binary format
	unsigned char uid[UID_SIZE];	// Fixed UID part of ticket
	unsigned char key[KEY_SIZE];	// AES key
	unsigned char accCode[ACC_CODE_SIZE]; // Access code to re-program device
	unsigned char fixedSize;	// Number of bytes in fixed field (0 if not used)
	unsigned char pgmSeq;		// Program sequence number (ignored at programming - updated by firmware)
	unsigned char tktFlags;		// Ticket configuration flags
	unsigned char cfgFlags;		// General configuration flags
	unsigned short ctrOffs;		// Counter offset value (ignored at programming - updated by firmware)
	unsigned short crc;		// CRC16 value of all fields
} CONFIG;

// Ticket flags

#define	TKTFLAG_TAB_FIRST	0x01	// Send TAB before first part
#define	TKTFLAG_APPEND_TAB1	0x02	// Send TAB after first part
#define	TKTFLAG_APPEND_TAB2	0x04	// Send TAB after second part
#define	TKTFLAG_APPEND_DELAY1	0x08	// Add 0.5s delay after first part
#define	TKTFLAG_APPEND_DELAY2	0x10	// Add 0.5s delay after second part
#define	TKTFLAG_APPEND_CR	0x20	// Append CR as final character

// Configuration flags

#define CFGFLAG_SEND_REF	0x01	// Send reference string (0..F) before data
#define	CFGFLAG_TICKET_FIRST	0x02	// Send ticket first (default is fixed part)
#define CFGFLAG_PACING_10MS	0x04	// Add 10ms intra-key pacing
#define CFGFLAG_PACING_20MS	0x08	// Add 20ms intra-key pacing
#define CFGFLAG_ALLOW_HIDTRIG	0x10	// Allow trigger through HID/keyboard
#define CFGFLAG_STATIC_TICKET	0x20	// Static ticket generation

// Navigation

#define	MAX_URL			48

typedef struct {
	unsigned char scancode[MAX_URL];// Scancode (lower 7 bits)
	unsigned char scanmod[MAX_URL >> 2];	// Modifier fields (packed 2 bits each)
	unsigned char flags;		// NAVFLAG_xxx flags
	unsigned char filler;		// Filler byte
	unsigned short crc;		// CRC16 value of all fields
} NAV;

#define	SCANMOD_SHIFT		0x80	// Highest bit in scancode
#define	SCANMOD_ALT_GR		0x01	// Lowest bit in mod
#define	SCANMOD_WIN		0x02	// WIN key

// Navigation flags

#define	NAVFLAG_INSERT_TRIG	0x01	// Automatic trigger when device is inserted
#define NAVFLAG_APPEND_TKT	0x02	// Append ticket to URL
#define	NAVFLAG_DUAL_KEY_USAGE	0x04	// Dual usage of key: Short = ticket  Long = Navigate

// Status block

typedef struct {
	unsigned char versionMajor;	// Firmware version information
	unsigned char versionMinor;
	unsigned char versionBuild;
	unsigned char pgmSeq;		// Programming sequence number. 0 if no valid configuration
	unsigned short touchLevel;	// Level from touch detector
} STATUS;

// Modified hex string mapping

#define	MODHEX_MAP		"cbdefghijklnrtuv"

#endif	// __YKDEF_H_INCLUDED__
