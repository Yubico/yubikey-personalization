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
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#ifdef _WIN32
#include <windows.h>
#include <errno.h>
#define ALLOC_THREADS(size) HANDLE *threads = malloc(sizeof(HANDLE) * times)
#define spawn_thread(thread, attr, start_routine, arg) thread = CreateThread(attr, 0, start_routine, arg, 0, NULL)
#define join_thread(thread, retval) WaitForSingleObject(thread, INFINITE)
#else
#include <pthread.h>
#define ALLOC_THREADS(size) pthread_t *threads = malloc(sizeof(pthread_t) * times)
#define spawn_thread(thread, attr, start_routine, arg) pthread_create(&thread, attr, start_routine, arg)
#define join_thread(thread, retval) pthread_join(thread, retval)
#endif
#define FREE_THREADS free(threads)

#include <ykpers.h>

void *start_thread(void *arg)
{
	if(!yk_init()) {
		printf("failed to init usb..\n");
		return NULL;
	}
	YK_STATUS *st = ykds_alloc();
	YK_KEY *yk = 0;
	yk_errno = 0;
	ykp_errno = 0;

	yk = yk_open_first_key();
	if(yk != 0) {
		yk_get_status(yk, st);
		yk_close_key(yk);
	}

	ykds_free(st);
	yk_release();
}

void _test_threaded_calls()
{
	int times = 5;
	int i;
	ALLOC_THREADS(times);

	for(i = 0; i < times; i++) {
		spawn_thread(threads[i], NULL, start_thread, NULL);
		join_thread(threads[i], NULL);
	}

	FREE_THREADS;
}

int main(void)
{
	_test_threaded_calls();

	return 0;
}

