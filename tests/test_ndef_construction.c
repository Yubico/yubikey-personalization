/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2011-2012 Yubico AB
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
#include <string.h>
#include <assert.h>

#include "ykcore/ykcore_lcl.h"
#include <ykpers.h>
#include <ykdef.h>

void _test_https_uri()
{
	YK_NDEF *ndef = ykp_alloc_ndef();
	char uri[] = "https://example.com/foo";
	int rc = ykp_construct_ndef_uri(ndef, uri);
	assert(rc == 1);
	assert(ndef->type == 'U');
	assert(ndef->data[0] == 0x04);
	assert(strncmp(ndef->data + 1, "example.com/foo", 15) == 0);
	assert(ndef->len == 16);
	ykp_free_ndef(ndef);
}

void _test_to_long_uri()
{
	YK_NDEF *ndef = ykp_alloc_ndef();
	char uri[] = "https://example.example.example.example.com/foo/kaka/bar/blahonga";
	int rc = ykp_construct_ndef_uri(ndef, uri);
	assert(rc == 0);
	assert(ndef->type == 0);
	assert(ndef->len == 0);
	ykp_free_ndef(ndef);
}

void _test_exact_uri()
{
	YK_NDEF *ndef = ykp_alloc_ndef();
	char uri[] = "https://www.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	int rc = ykp_construct_ndef_uri(ndef, uri);
	assert(rc == 1);
	assert(ndef->type == 'U');
	assert(ndef->data[0] == 0x02);
	assert(strncmp(ndef->data + 1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NDEF_DATA_SIZE -1) == 0);
	assert(ndef->len == NDEF_DATA_SIZE);
	ykp_free_ndef(ndef);
}

void _test_exact_text()
{
	YK_NDEF *ndef = ykp_alloc_ndef();
	char text[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	int rc = ykp_construct_ndef_text(ndef, text, "en", false);
	assert(rc == 1);
	assert(ndef->type == 'T');
	assert(ndef->data[0] == 2);
	assert(strncmp(ndef->data + 1, "en", 2) == 0);
	assert(strncmp(ndef->data + 3, text, NDEF_DATA_SIZE - 3) == 0);
	assert(ndef->len == NDEF_DATA_SIZE);
	ykp_free_ndef(ndef);
}

void _test_other_lang_text()
{
	YK_NDEF *ndef = ykp_alloc_ndef();
	char text[] = "aaaaaaaaaaaaaaa";
	size_t text_len = strlen(text);
	int rc = ykp_construct_ndef_text(ndef, text, "sv-SE", true);
	assert(rc == 1);
	assert(ndef->type == 'T');
	assert(ndef->data[0] == (0x80 & 5));
	assert(strncmp(ndef->data + 1, "sv-SE", 5) == 0);
	assert(strncmp(ndef->data + 6, text, text_len) == 0);
	assert(ndef->len == text_len + 6);
	ykp_free_ndef(ndef);
}

int main (void)
{
	_test_https_uri();
	_test_to_long_uri();
	_test_exact_uri();
	_test_exact_text();
	_test_other_lang_text();

	return 0;
}
