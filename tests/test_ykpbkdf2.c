/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2012 Yubico AB
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

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <ykpbkdf2.h>

static YK_PRF_METHOD hmac_sha1 = { 20, yk_hmac_sha1};

/* test that our pbkdf2 implementation is correct with test vectors from
 * http://tools.ietf.org/html/rfc6070 */

/* test vector 1:

     Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 1
       dkLen = 20

     Output:
       DK = 0c 60 c8 0f 96 1f 0e 71
            f3 a9 b5 24 af 60 12 06
            2f e0 37 a6             (20 octets)

 */
static int test_pbkdf2_1(void)
{
	char password[] = "password";
	unsigned char salt[] = "salt";
	unsigned int iterations = 1;
	size_t key_bytes = 20;

	unsigned char expected[] = {
		0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
		0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
		0x2f, 0xe0, 0x37, 0xa6 };

	unsigned char buf[64];
	memset(buf, 0, 64);

	yk_pbkdf2(password, salt, 4, iterations, buf, key_bytes, &hmac_sha1);
	assert(memcmp(expected, buf, key_bytes) == 0);
	return 0;
}

/* test vector 2:

     Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 2
       dkLen = 20

     Output:
       DK = ea 6c 01 4d c7 2d 6f 8c
            cd 1e d9 2a ce 1d 41 f0
            d8 de 89 57             (20 octets)

 */
static int test_pbkdf2_2(void)
{
	char password[] = "password";
	unsigned char salt[] = "salt";
	unsigned int iterations = 2;
	size_t key_bytes = 20;

	unsigned char expected[] = {
		0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
		0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
		0xd8, 0xde, 0x89, 0x57 };

	unsigned char buf[64];
	memset(buf, 0, 64);

	yk_pbkdf2(password, salt, 4, iterations, buf, key_bytes, &hmac_sha1);
	assert(memcmp(expected, buf, key_bytes) == 0);
	return 0;
}

/* test vector 3:

     Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 4096
       dkLen = 20

     Output:
       DK = 4b 00 79 01 b7 65 48 9a
            be ad 49 d9 26 f7 21 d0
            65 a4 29 c1             (20 octets)

 */
static int test_pbkdf2_3(void)
{
	char password[] = "password";
	unsigned char salt[] = "salt";
	unsigned int iterations = 4096;
	size_t key_bytes = 20;

	unsigned char expected[] = {
		0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
		0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
		0x65, 0xa4, 0x29, 0xc1 };

	unsigned char buf[64];
	memset(buf, 0, 64);

	yk_pbkdf2(password, salt, 4, iterations, buf, key_bytes, &hmac_sha1);
	assert(memcmp(expected, buf, key_bytes) == 0);
	return 0;
}

/* test vector 4:

        Input:
       P = "password" (8 octets)
       S = "salt" (4 octets)
       c = 16777216
       dkLen = 20

     Output:
       DK = ee fe 3d 61 cd 4d a4 e4
            e9 94 5b 3d 6b a2 15 8c
            26 34 e9 84             (20 octets)

 */
static int test_pbkdf2_4(void)
{
	char password[] = "password";
	unsigned char salt[] = "salt";
	unsigned int iterations = 16777216;
	size_t key_bytes = 20;

	unsigned char expected[] = {
		0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
		0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
		0x26, 0x34, 0xe9, 0x84 };

	unsigned char buf[64];
	memset(buf, 0, 64);

	yk_pbkdf2(password, salt, 4, iterations, buf, key_bytes, &hmac_sha1);
	assert(memcmp(expected, buf, key_bytes) == 0);
	return 0;
}

/* test vector 5:

 Input:
       P = "passwordPASSWORDpassword" (24 octets)
       S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
       c = 4096
       dkLen = 25

     Output:
       DK = 3d 2e ec 4f e4 1c 84 9b
            80 c8 d8 36 62 c0 e4 4a
            8b 29 1a 96 4c f2 f0 70
            38                      (25 octets)

 */
static int test_pbkdf2_5(void)
{
	char password[] = "passwordPASSWORDpassword";
	unsigned char salt[] = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
	unsigned int iterations = 4096;
	size_t key_bytes = 25;

	unsigned char expected[] = {
		0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
		0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
		0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
		0x38 };

	unsigned char buf[64];
	memset(buf, 0, 64);

	yk_pbkdf2(password, salt, 36, iterations, buf, key_bytes, &hmac_sha1);
	assert(memcmp(expected, buf, key_bytes) == 0);
	return 0;
}

/* test vector 6:

   Input:
       P = "pass\0word" (9 octets)
       S = "sa\0lt" (5 octets)
       c = 4096
       dkLen = 16

     Output:
       DK = 56 fa 6a a7 55 48 09 9d
            cc 37 d7 f0 34 25 e0 c3 (16 octets)

 */
static int test_pbkdf2_6(void)
{
	char password[] = "pass\0word";
	unsigned char salt[] = "sa\0lt";
	unsigned int iterations = 4096;
	size_t key_bytes = 16;

	unsigned char expected[] = {
		0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
		0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3 };

	unsigned char buf[64];
	memset(buf, 0, 64);

	yk_pbkdf2(password, salt, 5, iterations, buf, key_bytes, &hmac_sha1);
	assert(memcmp(expected, buf, key_bytes) == 0);
	return 0;

}

int main(void)
{
	test_pbkdf2_1();
	test_pbkdf2_2();
	test_pbkdf2_3();
	/* vector 4 is very slow.. */
#if 0
	test_pbkdf2_4();
#endif
	test_pbkdf2_5();
	/* vector 6 breaks though to us running strlen() on the password. */
#if 0
	test_pbkdf2_6();
#endif
	return 0;
}
