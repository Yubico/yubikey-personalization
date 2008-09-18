/*************************************************************************
**                                                                      **
**      Y K U T I L  -  Yubikey utilities				**
**                                                                      **
**      Copyright 2008 Yubico AB					**
**                                                                      **
**      Date		/ Sig / Rev  / History				**
**      2008-06-05	/ J E / 0.00 / Main				**
**                                                                      **
*************************************************************************/

#include <ykdef.h>

#define	CRC_OK_RESIDUE	0xf0b8

extern unsigned short getCRC(const unsigned char *, int);
extern int modhexDecode(unsigned char *, const unsigned char *, int);
extern int parseOTP(TICKET *tkt, unsigned char *fixed, int *fixedSize, const char *str, const unsigned char *key);

