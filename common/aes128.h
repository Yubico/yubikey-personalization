/*************************************************************************
**                                                                      **
**      A E S 1 2 8  -  AES-128 encryption and decryption				**
**                                                                      **
**      Copyright 2008 Yubico AB										**
**                                                                      **
**      Date		/ Sig / Rev  / History                              **
**      2008-06-05	/ J E / 0.00 / Main									**
**                                                                      **
*************************************************************************/

extern void aesEncrypt(unsigned char *state, const unsigned char *key);
extern void aesDecrypt(unsigned char *state, const unsigned char *key);
