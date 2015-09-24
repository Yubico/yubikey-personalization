/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2009-2015 Yubico AB
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

#include <ykpers.h>
#include <ykpers-version.h>
#include <stdio.h>
#include <string.h>

int main (void)
{
	YKP_CONFIG *ykp;
	int rc;

	if (strcmp (YKPERS_VERSION_STRING, ykpers_check_version (NULL)) != 0)
	{
		printf ("version mismatch %s != %s\n",YKPERS_VERSION_STRING,
			ykpers_check_version (NULL));
		return 1;
	}

	if (ykpers_check_version (YKPERS_VERSION_STRING) == NULL)
	{
		printf ("version NULL?\n");
		return 1;
	}

	if (ykpers_check_version ("99.99.99") != NULL)
	{
		printf ("version not NULL?\n");
		return 1;
	}

	ykp = ykp_alloc ();
	if (!ykp)
	{
		printf ("ykp_alloc returned NULL\n");
		return 1;
	}

	rc = ykp_free_config(ykp);
	if (!rc)
	{
		printf ("ykp_free_config => %d\n", rc);
		return 1;
	}

	return 0;
}
