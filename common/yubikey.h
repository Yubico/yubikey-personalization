/*************************************************************************
**                                                                      **
**      Y U B I K E Y  -  Basic LibUSB programming API for the Yubikey	**
**                                                                      **
**      Copyright 2008 Yubico AB					**
**                                                                      **
**      Date		/ Sig / Rev  / History				**
**      2008-06-05	/ J E / 0.00 / Main				**
**                                                                      **
**************************************************************************
**
**	For binary compatibility, ykdef structures must be byte-aligned
**	Furthermore - define ENDIAN_SWAP appropriately
*/

#ifdef _WIN32
#pragma pack(push, 1)
#endif

#include <ykdef.h>

#ifdef _WIN32
#pragma pack(pop)
#endif

#ifdef _WIN32
// Little endian
#define	ENDIAN_SWAP(x)
#else
// Big endian
#define	ENDIAN_SWAP(x)	x = ((x) >> 8) | ((x) << 8)
#endif

typedef void YUBIKEY;

extern int ykInit(void);
extern YUBIKEY * ykOpen(void);
extern void ykClose(YUBIKEY *);
extern int ykGetStatus(YUBIKEY *, STATUS *, int);
extern int ykWriteConfig(YUBIKEY *, CONFIG *, unsigned char *);
