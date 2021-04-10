/*
 *  $Id: knock.h,v 1.1.1.1 2002/03/13 21:01:12 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  knock.h - Port Scanning Technique example code
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

#include <libnet.h>
#include <pcap.h>
 
#define SNAPLEN         94          /* Ethernet + IP + opt + TCP */
#define PROMISC         1
#define TIMEOUT         500
#define PORT_OPEN       0
#define PORT_CLOSED     1
#define PORT_OPEN_TIMEDOUT   2
#define PORT_CLOSED_TIMEDOUT 3
#define SOURCE_PORT     31337

struct knock_pack
{
    pcap_t *p;                      /* pcap descriptor */
    struct pcap_pkthdr h;           /* pcap packet header */
    libnet_t *l;                    /* libnet descriptor */
    libnet_ptag_t ip;               /* IP header */
    libnet_ptag_t tcpudp;           /* TCP or UDP header */
    libnet_plist_t *plist;          /* libnet port list */
    u_long src_ip;                  /* our IP address */
    u_long dst_ip;                  /* host to scan */
    u_char flags;                   /* control flags */
    u_char to;                      /* packet read timeout */
#define NETWORK_TIMEOUT 2           /* 2 seconds and we're crying foul */
    u_char scan_type;               /* either TCP or UDP! */
#define SCAN_TCP        0           /* TCP */
#define SCAN_UDP        1           /* UDP */
    u_char scan_subtype;            /* TCP scan subtype */
#define SCAN_TCP_SYN    1           /* Half-open scan */
#define SCAN_TCP_FIN    2           /* Stealth FIN scan */
#define SCAN_TCP_XMAS   3           /* Stealth XMAS scan */
    u_short port;                   /* current port we're scanning */
    u_char *packet;                 /* everyone's favorite: packet! */
    u_short ports_open;             /* open ports */
    char errbuf[LIBNET_ERRBUF_SIZE];
};


struct knock_pack *knock_init(char *, u_char, char *, u_char, u_char, 
        u_char, char *, char *);
void knock_destroy(struct knock_pack *);
void knock(struct knock_pack *);
int build_packet(struct knock_pack *);
int write_packet(struct knock_pack *);
int receive_packet(struct knock_pack *);
void cleanup(int);
int catch_sig(int, void(*)());
void usage(char *);

/* EOF */
