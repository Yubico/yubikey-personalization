/* -*- mode:C; c-file-style: "bsd" -*- */
/* Copyright (c) 2008-2013 Yubico AB
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

#include <string.h>

#include <ykpbkdf2.h>

#include "sha.h"

int yk_hmac_sha1(const char *key, size_t key_len,
		     const char *text, size_t text_len,
		     uint8_t *output, size_t output_size)
{
	if (output_size < SHA1HashSize)
		return 0;

	if (hmac(SHA1,
		 (const unsigned char *)text, (int)text_len,
		 (const unsigned char *)key, (int)key_len,
		 output))
		return 0;
	return 1;
}

int yk_pbkdf2(const char *passphrase,
	      const unsigned char *salt, size_t salt_len,
	      unsigned int iterations,
	      unsigned char *dk, size_t dklen,
	      YK_PRF_METHOD *prf_method)
{
	size_t l = ((dklen - 1 + prf_method->output_size)
		    / prf_method->output_size);
#if 0 /* r for "rest" is unused but may be interesting in the future */
	size_t r = dklen - ((l - 1) * prf_method->output_size);
#endif

	unsigned int block_count;

	memset(dk, 0, dklen);

	for (block_count = 1; block_count <= l; block_count++) {
		unsigned char block[256]; /* A big chunk, that's 2048 bits */
		size_t block_len;
		unsigned int iteration;
		size_t i;

		memcpy(block, salt, salt_len);
		block[salt_len + 0] = (block_count & 0xff000000) >> 24;
		block[salt_len + 1] = (block_count & 0x00ff0000) >> 16;
		block[salt_len + 2] = (block_count & 0x0000ff00) >>  8;
		block[salt_len + 3] = (block_count & 0x000000ff) >>  0;
		block_len = salt_len + 4;

		for (iteration = 0; iteration < iterations; iteration++) {
			if (!prf_method->prf_fn(passphrase, strlen(passphrase),
						(char *)block, block_len,
						block, sizeof(block)))
				return 0;
			block_len = prf_method->output_size;
			for(i = 0; i < dklen; i++) {
				dk[i] ^= block[i];
			}
		}

		if (block_len > dklen)
			block_len = dklen; /* This happens in the last block */
		dk += block_len;
		dklen -= block_len;
	}
	return 1;
}
