/* -*- mode:C; c-file-style: "bsd" -*- */
/*
 * Copyright (c) 2008-2014 Yubico AB
 * Copyright (c) 2010 Tollef Fog Heen <tfheen@err.no>
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

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <ykpers.h>
#include <ykdef.h>
#include <ykpers-version.h>

#include "ykpers-args.h"

int main(int argc, char **argv)
{
	FILE *inf = NULL; const char *infname = NULL;
	FILE *outf = NULL; const char *outfname = NULL;
	int data_format = YKP_FORMAT_LEGACY;
	bool verbose = false;
	char keylocation = 0;
	bool use_access_code = false;
	unsigned char access_code[256];
	unsigned char scan_codes[sizeof(SCAN_MAP)];
	YK_KEY *yk = 0;
	YKP_CONFIG *cfg = ykp_alloc();
	YK_STATUS *st = ykds_alloc();
	bool autocommit = false;
	char data[1024];
	bool dry_run = false;

	/* Options */
	char oathid[128] = {0};
	char ndef_string[128] = {0};
	char ndef_type = 0;
	unsigned char usb_mode = 0;
	unsigned char cr_timeout = 0;
	unsigned short autoeject_timeout = 0;
	int num_modes_seen = 0;
	bool zap = false;
	int key_index = 0;

	/* Assume the worst */
	bool error = true;
	int exit_code = 0;

	int c;

	ykp_errno = 0;
	yk_errno = 0;

	while((c = getopt(argc, argv, optstring)) != -1) {
		switch(c) {
			case 'h':
				fputs(usage, stderr);
				exit(0);
			case 'N':
				key_index = atoi(optarg);
				break;
			case 'V':
				fputs(YKPERS_VERSION_STRING "\n", stderr);
				return 0;
			case ':':
				switch(optopt) {
					case 'S':
						continue;
					case 'a':
						continue;
				}
				fprintf(stderr, "Option %c requires an argument.\n", optopt);
				exit(1);
				break;
			default:
				continue;
		}
	}
	optind = 1;

	if (!yk_init()) {
		exit_code = 1;
		goto err;
	}

	if (!(yk = yk_open_key(key_index))) {
		exit_code = 1;
		goto err;
	}

	if (!yk_get_status(yk, st)) {
		exit_code = 1;
		goto err;
	}

	printf("Firmware version %d.%d.%d Touch level %d ",
	       ykds_version_major(st),
	       ykds_version_minor(st),
	       ykds_version_build(st),
	       ykds_touch_level(st));
	if (ykds_pgm_seq(st))
		printf("Program sequence %d\n",
		       ykds_pgm_seq(st));
	else
		printf("Unconfigured\n");

	if (!(yk_check_firmware_version2(st))) {
		if (yk_errno == YK_EFIRMWARE) {
			printf("Unsupported firmware revision - some "
			       "features may not be available\n"
			       "Please see \n"
			       "https://developers.yubico.com/yubikey-personalization/doc/Compatibility.html\n"
			       "for more information.\n");
		} else {
			goto err;
		}
	}

	/* Parse all arguments in a testable way */
	if (! args_to_config(argc, argv, cfg, oathid,
			     &infname, &outfname,
			     &data_format, &autocommit,
			     st, &verbose, &dry_run,
			     access_code, &use_access_code,
			     &keylocation, &ndef_type, ndef_string,
			     &usb_mode, &zap, scan_codes, &cr_timeout,
			     &autoeject_timeout, &num_modes_seen, &exit_code)) {
		goto err;
	}

	if (oathid[0] != 0) {
		set_oath_id(oathid, cfg, yk, st);
	}

	if (verbose && (ykds_version_major(st) > 2 ||
			(ykds_version_major(st) == 2 &&
			 ykds_version_minor(st) >= 2) ||
			(ykds_version_major(st) == 2 && // neo has serial functions
			 ykds_version_minor(st) == 1 &&
			 ykds_version_build(st) >= 4))) {
		unsigned int serial;
		if (! yk_get_serial(yk, 0, 0, &serial)) {
			printf ("Failed to read serial number (serial-api-visible disabled?).\n");

		} else {
			printf ("Serial number : %i\n", serial);
		}
	}

	printf ("\n");

	if (infname) {
		if (strcmp(infname, "-") == 0)
			inf = stdin;
		else
			inf = fopen(infname, "r");
		if (inf == NULL) {
			fprintf(stderr,
				"Couldn't open %s for reading: %s\n",
				infname,
				strerror(errno));
			exit_code = 1;
			goto err;
		}
	}

	if (outfname) {
		if (strcmp(outfname, "-") == 0)
			outf = stdout;
		else
			outf = fopen(outfname, "w");
		if (outf == NULL) {
			fprintf(stderr,
				"Couldn't open %s for writing: %s\n",
				outfname,
				strerror(errno));
			exit(1);
		}
	}

	if (inf) {
		if(!ykp_clear_config(cfg))
			goto err;
		if(!fread(data, 1, 1024, inf))
			goto err;
		if (!ykp_import_config(cfg, data, strlen(data), data_format))
			goto err;
	}
	if (! zap && (ykp_command(cfg) == SLOT_CONFIG || ykp_command(cfg) == SLOT_CONFIG2)) {
		int key_bytes = ykp_get_supported_key_length(cfg);
		char keybuf[42];
		size_t keylen;
		if(keylocation == 2) {
			if(key_bytes == 20) {
				fprintf(stderr, " HMAC key, 20 bytes (40 characters hex) : ");
			} else {
				fprintf(stderr, " AES key, 16 bytes (32 characters hex) : ");
			}
			fflush(stderr);
			if(!fgets(keybuf, sizeof(keybuf), stdin)) {
				printf("error?\n");
				perror ("fgets");
				exit_code = 1;
				goto err;
			}
			keylen = strnlen(keybuf, sizeof(keybuf));
			if(keybuf[keylen - 1] == '\n') {
				keybuf[keylen - 1] = '\0';
			}
			if(key_bytes == 20) {
				if(ykp_HMAC_key_from_hex(cfg, keybuf)) {
					goto err;
				}
			} else {
				if(ykp_AES_key_from_hex(cfg, keybuf)) {
					goto err;
				}
			}
		} else if(keylocation == 0) {
			const char *random_places[] = {
				"/dev/srandom",
				"/dev/urandom",
				"/dev/random",
				0
			};
			const char **random_place;
			size_t read_bytes = 0;

			for (random_place = random_places; *random_place; random_place++) {
				FILE *random_file = fopen(*random_place, "r");
				if (random_file) {
					read_bytes = 0;

					while (read_bytes < key_bytes) {
						size_t n = fread(&keybuf[read_bytes], 1,
								key_bytes - read_bytes, random_file);
						read_bytes += n;
					}

					fclose(random_file);
					break;
				}
			}
			if(read_bytes < key_bytes) {
				ykp_errno = YKP_ENORANDOM;
				goto err;
			}
			if(key_bytes == 20) {
				if(ykp_HMAC_key_from_raw(cfg, keybuf)) {
					goto err;
				}
			} else {
				if(ykp_AES_key_from_raw(cfg, keybuf)) {
					goto err;
				}
			}
		}
	}

	if (outf) {
		if(!(ykp_export_config(cfg, data, 1024, data_format))) {
			goto err;
		}
		if(!(fwrite(data, 1, strlen(data), outf))) {
			goto err;
		}
	} else {
		char commitbuf[256]; size_t commitlen;

		if (ykp_command(cfg) == SLOT_SWAP) {
			fprintf(stderr, "Configuration in slot 1 and 2 will be swapped\n");
		} else if(ykp_command(cfg) == SLOT_NDEF || ykp_command(cfg) == SLOT_NDEF2) {
			fprintf(stderr, "New NDEF will be written as:\n%s\n", ndef_string);
		} else if(ykp_command(cfg) == SLOT_DEVICE_CONFIG) {
			fprintf(stderr, "The USB mode will be set to: 0x%x\n", usb_mode);
			if(num_modes_seen > 1) {
				fprintf(stderr, "The challenge response timeout will be set to: %d\n", cr_timeout);
				if(num_modes_seen > 2) {
					fprintf(stderr, "The smartcard autoeject timeout will be set to: %d\n", autoeject_timeout);
				}
			}
		} else if(ykp_command(cfg) == SLOT_SCAN_MAP) {
			fprintf(stderr, "A new scanmap will be written.\n");
		} else if(zap) {
			fprintf(stderr, "Configuration in slot %d will be deleted\n", ykp_config_num(cfg));
		} else {
			if (ykp_command(cfg) == SLOT_CONFIG || ykp_command(cfg) == SLOT_CONFIG2) {
				fprintf(stderr, "Configuration data to be written to key configuration %d:\n\n", ykp_config_num(cfg));
			} else {
				fprintf(stderr, "Configuration data to be updated in key configuration %d:\n\n", ykp_command(cfg) == SLOT_UPDATE1 ? 1 : 2);
			}
			ykp_export_config(cfg, data, 1024, YKP_FORMAT_LEGACY);
			fwrite(data, 1, strlen(data), stderr);
		}
		fprintf(stderr, "\nCommit? (y/n) [n]: ");
		if (autocommit) {
			strcpy(commitbuf, "yes");
			puts(commitbuf);
		} else {
			if (!fgets(commitbuf, sizeof(commitbuf), stdin))
			{
				perror ("fgets");
				goto err;
			}
		}
		commitlen = strlen(commitbuf);
		if (commitbuf[commitlen - 1] == '\n')
			commitbuf[commitlen - 1] = '\0';
		if (strcmp(commitbuf, "y") == 0
		    || strcmp(commitbuf, "yes") == 0) {
			exit_code = 2;

			if (verbose)
				printf("Attempting to write configuration to the yubikey...");
			if (dry_run) {
				printf("Not writing anything to key due to dry_run requested.\n");
			}
			else if(ykp_command(cfg) == SLOT_NDEF || ykp_command(cfg) == SLOT_NDEF2) {
				YK_NDEF *ndef = ykp_alloc_ndef();
				int confnum = 1;
				int res = 0;
				if(ndef_type == 'U') {
					res = ykp_construct_ndef_uri(ndef, ndef_string);
				} else if(ndef_type == 'T') {
					res = ykp_construct_ndef_text(ndef, ndef_string, "en", false);
				}
				if(!res) {
					if(verbose) {
						printf(" failure to construct ndef\n");
					}
					goto err;
				}
				if(use_access_code) {
					if(!ykp_set_ndef_access_code(ndef, access_code)) {
						if(verbose) {
							printf(" failure to set ndef accesscode\n");
						}
						goto err;
					}
				}
				if(ykp_command(cfg) == SLOT_NDEF2) {
					confnum = 2;
				}
				if (!yk_write_ndef2(yk, ndef, confnum)) {
					if (verbose)
						printf(" failure to write ndef\n");
					goto err;
				}
				ykp_free_ndef(ndef);
			} else if(ykp_command(cfg) == SLOT_DEVICE_CONFIG) {
				YK_DEVICE_CONFIG *device_config = ykp_alloc_device_config();
				ykp_set_device_mode(device_config, usb_mode);
				if(num_modes_seen > 1) {
					ykp_set_device_chalresp_timeout(device_config, cr_timeout);
					if(num_modes_seen > 2) {
						ykp_set_device_autoeject_time(device_config, autoeject_timeout);
					}
				}

				if((usb_mode & 0xf) == MODE_CCID || (usb_mode & 0xf) == MODE_U2F ||
						(usb_mode & 0xf) == MODE_U2F_CCID) {
					fprintf(stderr, "WARNING: Changing mode will require you to use another tool (ykneomgr or u2f-host) to switch back if OTP mode is disabled, really commit? (y/n) [n]: ");
					if (autocommit) {
						strcpy(commitbuf, "yes");
						puts(commitbuf);
					} else {
						if (!fgets(commitbuf, sizeof(commitbuf), stdin))
						{
							perror ("fgets");
							goto err;
						}
					}
					commitlen = strlen(commitbuf);
					if (commitbuf[commitlen - 1] == '\n')
						commitbuf[commitlen - 1] = '\0';
					if (strcmp(commitbuf, "y") != 0
							&& strcmp(commitbuf, "yes") != 0) {
						exit_code = 0;
						error = false;
						goto err;
					}
				}

				if(!yk_write_device_config(yk, device_config)) {
					if(verbose)
						printf(" failure\n");
					goto err;
				}
				ykp_free_device_config(device_config);


			} else if(ykp_command(cfg) == SLOT_SCAN_MAP) {
				if(!yk_write_scan_map(yk, scan_codes)) {
					if(verbose)
						printf(" failure\n");
					goto err;
				}
			} else {
				YK_CONFIG *ycfg = NULL;
				/* if we're deleting a slot we send the configuration as NULL */
				if (!zap) {
					ycfg = ykp_core_config(cfg);
				}
				if (!yk_write_command(yk,
							ycfg, ykp_command(cfg),
							use_access_code ? access_code : NULL)) {
					if (verbose)
						printf(" failure\n");
					goto err;
				}
			}

			if (verbose && !dry_run)
				printf(" success\n");
		}
	}

	exit_code = 0;
	error = false;

err:
	if (error) {
		report_yk_error();
	}

	if (st)
		free(st);
	if (inf)
		fclose(inf);
	if (outf)
		fclose(outf);

	if (yk && !yk_close_key(yk)) {
		report_yk_error();
		exit_code = 2;
	}

	if (!yk_release()) {
		report_yk_error();
		exit_code = 2;
	}

	if (cfg)
		ykp_free_config(cfg);

	exit(exit_code);
}
