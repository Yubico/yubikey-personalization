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

#include "ykutil.h"
#include "yubikey.h"
#include <string.h>
#include <ctype.h>
#include <aes128.h>

/*************************************************************************
**  function getCRC							**
**  Calculate ISO13239 checksum of buffer				**
**                                                                      **
**	unsigned short getCRC(const unsigned char *buf, int bcnt)	**
**                                                                      **
**  Where:                                                              **
**	"buf" is pointer to buffer					**
**	"bcnt" is size of the buffer					**
**									**
**	Returns: ISO13239 checksum					**
**                                                                      **
*************************************************************************/

unsigned short getCRC(const unsigned char *buf, int bcnt)
{
	unsigned short crc = 0xffff;
	int i;

	while (bcnt--) {
		crc ^= *buf++;
		for (i = 0; i < 8; i++) crc = (crc & 1) ? ((crc >> 1) ^ 0x8408) : (crc >> 1);
	}

	return crc;
}

/*************************************************************************
**  function modhexDecode						**
**  Decodes modhex string into binary					**
**                                                                      **
**	int modhexDecode(unsigned char *dst, const unsigned char *src,	**
**					 int dstSize)			**
**                                                                      **
**  Where:                                                              **
**	"dst" is pointer to decoded binary data				**
**	"src" is pointer to modhex string				**
**	"dstSize" is size of the destination buffer			**
**									**
**	Returns: Number of bytes decoded				**
**                                                                      **
*************************************************************************/

int modhexDecode(unsigned char *dst, const unsigned char *src, int dstSize)
{
	static const char trans[] = MODHEX_MAP;
	unsigned char b, flag = 0;
	int bcnt;
	char *p1;

	for (bcnt = 0; *src && (bcnt < dstSize); src++) {
		if (p1 = strchr(trans, tolower(*src)))
			b = (unsigned char) (p1 - trans);
		else
			b = 0;

		if (flag = !flag) 
			*dst = b;
		else {
			*dst = (*dst << 4) | b;
			dst++;
			bcnt++;
		}
	}

	return bcnt;
}

/*************************************************************************
**  function parseOTP							**
**  Parses OTP string and inserts result in TICKET structure		**
**                                                                      **
**	int parseOTP(TICKET *tkt, unsigned char *fixed,			**
**				 int *fixedSize, const char *str,	**
**				 const char *key)			**
**                                                                      **
**  Where:                                                              **
**	"tkt" is pointer to receiving TICKET structure			**
**	"fixed" is pointer to receiving fixed part buffer		**
**	"fixedSize" is pointer to receiving size of fixed part		**
**	"str" is pointer to ascii OTP string				**
**	"key" is pointer to AES key					**
**									**
**	Returns: Nonzero if successful, zero otherwise			**
**                                                                      **
*************************************************************************/

int parseOTP(TICKET *tkt, unsigned char *fixed, int *fixedSize, const char *str, const unsigned char *key)
{
	int i, j;
	unsigned char bin[FIXED_SIZE + sizeof(TICKET)];

	// Convert from modhex to binary. Must be at least sizeof(TICKET) bytes

	if ((i = modhexDecode(bin, str, sizeof(bin))) < sizeof(TICKET)) return 0;

	// The ticket is located in the last 16 bytes

	memcpy(tkt, bin + i - sizeof(TICKET), sizeof(TICKET));

	// Decrypt the stuff

	aesDecrypt((unsigned char *) tkt, key);

	// Is the checksum okay ?

	j = getCRC((unsigned char *) tkt, sizeof(TICKET));
	ENDIAN_SWAP(j);
	if (j != CRC_OK_RESIDUE) return 0;

	// Shape up little-endian fields (if applicable)

	ENDIAN_SWAP(tkt->rnd);
	ENDIAN_SWAP(tkt->tstpl);
	ENDIAN_SWAP(tkt->useCtr);

	// Insert fixed id (if present)

	*fixedSize = i - sizeof(TICKET);
	
	if (*fixedSize) memcpy(fixed, bin, *fixedSize);

	return 1;
}
