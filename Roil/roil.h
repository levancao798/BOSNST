/*
 *  $Id: roil.h,v 1.1 2002/04/11 04:42:06 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  roil.h - openssl example code
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "/usr/local/ssl/include/openssl/evp.h"
 
#define KEY_LENGTH      0x100           /* max passphrase size */
#define IV_LENGTH       0x008           /* IV length */
#define RETRY_THRESHOLD 0x003           /* password retries */ 
#define BUF_SIZE        0x100           /* 256 byte buffer */
#define ERRBUF_SIZE     0x100           /* 256 byte buffer */

/* magic file header number */
u_char magic[] = {0x0f, 0x01, 0x02, 0x0d, 0xff, 0xee, 0xf1, 0x43};

struct roil_pack
{
    int fd_in;
    int fd_out;
    char fn_in[100];
    char fn_out[100];
    char passphrase[KEY_LENGTH];
    u_char flags;
#define MD          0x01                /* Hash */
#define MD_FROMFILE 0x02                /* Hash from a file */
#define ENCRYPT     0x04                /* Encrypt */
#define DECRYPT     0x08                /* Decrypt */
    char md[10];
    char ea[10];
    char errbuf[ERRBUF_SIZE];
};

struct roil_pack *roil_init(char *, u_char, char *, char *, char *);
int open_outputfile(struct roil_pack *);
void roil_destroy(struct roil_pack *);
void roil(struct roil_pack *);
u_char *roil_digest(struct roil_pack *, int *);
int roil_cipher(struct roil_pack *);
int get_passphrase(char *);
int make_key(struct roil_pack *, u_char *);
void get_iv(u_char *);
void usage(char *);


/* EOF */
