/*
 *  $Id: clutch.h,v 1.3 2002/05/05 22:27:28 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  clutch.h - libdnet example code
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

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dnet.h>


/* mode types */
#define ARP     0x1
#define ROUTE   0x2

/* control flags */
#define VERBOSE 0x1
#define ENFORCE 0x2

/* simple macros for code clean up */
#define STEPOVER_WS(b)              \
        while (!isgraph(*b))        \
        {                           \
            b++;                    \
        }                           \

#define STEPOVER_NONWS(b)           \
        while (isgraph(*b))         \
        {                           \
            b++;                    \
        }                           \

struct clutch_pack
{
    u_char flags;               /* control flags */
    arp_t *a;                   /* arp cache handle */
    route_t *r;                 /* route table handle */
    struct clutch_arp_entry *cae;/* linked list of arp cache entries */
    struct clutch_route_entry *cre;/* linked list of route table entries */
};


struct clutch_arp_entry
{
    struct addr mac;                /* ethernet address */
    struct addr ip;                 /* ip address */
    struct clutch_arp_entry *next;  /* next entry in list */
};


struct clutch_route_entry
{
    struct addr ip;                 /* ip address */
    struct addr gw;                 /* gateway */
    struct clutch_route_entry *next;/* next entry in list */
};


int clutch_init(struct clutch_pack *, char *);
int parse_config(struct clutch_pack *, FILE *);
int new_list_entry(struct clutch_pack **, int, struct addr *,
        struct addr *);
char *get_time();
void free_cp(struct clutch_pack *);
int check_arp_cache(const struct arp_entry *, void *);
int check_route_table(const struct route_entry *, void *);
void usage(char *);

/* EOF */
