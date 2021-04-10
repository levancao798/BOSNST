/*
 *  $Id: lilt.h,v 1.7 2002/01/02 02:43:02 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  lilt.h - libnids example code
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <termios.h>
#include <ctype.h>
#include <time.h>
#include <nids.h>

/*
 *  The following two structures taken from libnids sources to be used
 *  in the reporting function.
 */

struct scan
{
    u_int addr;
    unsigned short port;
    u_char flags;
};


struct host
{
    struct host *next;
    struct host *prev;
    u_int addr;
    int modtime;
    int n_packets;
    struct scan *packets;
};


struct lilt_pack
{
#define M_LEN       128 /* this should be more than enough */
    u_short mon[M_LEN]; /* list of TCP WKP to monitor */
    u_char flags;       /* control flags */
#define LP_CONN     0x1 /* there is a connection to watch */
#define LP_WATCH    0x2 /* watch this connection */
#define LP_KILL     0x4 /* kill this connection */
#define LP_DISCARD  0x8 /* discard this connection */
    struct tuple4 t;    /* four tuple of the connection in question */
    int tcp_count;      /* number of TCP connections seen */
    int tcp_killed;     /* number of TCP connections killed */
    int ps_count;       /* number of port scans seen */
};

char *cull_address(struct tuple4);
char *get_time();
int set_ports(char *);
void monitor_tcp(struct tcp_stream *, void *);
void report(int, int, void *, void *);
void command_summary();
void usage(char *);
int interesting(u_short);
void lock_tuple(struct tuple4);
int our_tuple(struct tuple4);
void process_command();

/* EOF */
