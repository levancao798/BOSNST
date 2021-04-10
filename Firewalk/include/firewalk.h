/*
 *  $Id: firewalk.h,v 1.6 2002/05/15 06:46:54 route Exp $
 *
 *  Firewalk 5.0
 *  firewalk.h - Interface
 *
 *  Copyright (c) 1998 - 2002 Mike D. Schiffman  <mike@infonexus.com>
 *  Copyright (c) 1998, 1999 David E. Goldsmith <dave@infonexus.com>
 *  http://www.packetfactory.net/firewalk
 *
 * All rights reserved.
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
 */

#ifndef _FIREWALK_H
#define _FIREWALK_H

#include <setjmp.h>
#include <ctype.h>
#include <pcap.h>
#include <dnet.h>
#include <libnet.h>

#define FW_BANNER  "Firewalk (c) 2002 Mike D. Schiffman \
<mike@infonexus.com>\nhttp://www.packetfactory.net/firewalk\n\
for more information.\n"

/* responses for the ramping phase */
#define FW_NO_REPLY                     0x00
#define FW_PACKET_IS_BORING             0x01
#define FW_PACKET_IS_TTL_EX_EN_ROUTE    0x02
#define FW_PACKET_IS_UNREACH_EN_ROUTE   0x03
#define FW_PACKET_IS_TERMINAL_TTL_EX    0x04
#define FW_PACKET_IS_TERMINAL_UNREACH   0x05
#define FW_PACKET_IS_TERMINAL_SYNACK    0x06
#define FW_PACKET_IS_TERMINAL_RST       0x07

/* responses for the scanning phase */
#define FW_PORT_IS_OPEN_SYNACK          0x08
#define FW_PORT_IS_OPEN_RST             0x09
#define FW_PORT_IS_OPEN_UNREACH         0x0a
#define FW_PORT_IS_OPEN_TTL_EX          0x0b

/* misc responses */
#define FW_ABORT_SCAN                   0xfd
#define FW_USER_INTERRUPT               0xfe
#define FW_SERIOUS_ERROR                0xff

/* default libpcap timeout */
#define FW_REPLY_TIMEOUT                0x02   

/* snapshot length */
#define FW_SNAPLEN                      0x60
#define FW_DEFAULT_PORT_LIST           "1-130,139,1025"

/* various minimums and maximums */
#define FW_PORT_MAX                     0xffff
#define FW_PORT_MIN                     0x00
#define FW_PCAP_TIMEOUT_MAX             0x3e8
#define FW_PCAP_TIMEOUT_MIN             0x01
#define FW_IP_HOP_MAX                   0x19
#define FW_IP_HOP_MIN                   0x01
#define FW_XV_MAX                       0x08
#define FW_XV_MIN                       0x01

/* BPF filter strings */
#define FW_BPF_FILTER_UDP  "icmp[0] == 11 or icmp[0] == 3 or udp"
#define FW_BPF_FILTER_TCP  "icmp[0] == 11 or icmp[0] == 3 or tcp[13] ==\
                            0x12 or tcp[13] == 0x4 or tcp[13] == 0x14"

/* checks if an IP packet inside of ICMP error message is ours */
#define FW_IS_OURS(ip, fp)                  \
        (ntohs(ip->ip_id) ==                \
        (*fp)->id && ip->ip_src.s_addr ==   \
        (*fp)->sin.sin_addr.s_addr) !=0

/* firewalk statistics structure */
struct firepack_stats
{
    u_short ports_total;            /* number of ports scanned */
    u_short ports_open;             /* open ports */
    u_short ports_unknown;          /* unknown ports */
    u_long packets_sent;            /* packets sent */
    u_long packets_err;             /* packets errors */
    u_long packets_caught;          /* packets we caught total */
    u_short packets_caught_interesting; /* packets we cared about */
};

/* main monolithic firewalk context structure */
struct firepack
{
    char *device;                   /* interface */
    u_char *packet;                 /* packet captured from the wire */
    pcap_t *p;                      /* libpcap context */
    libnet_t *l;                    /* libnet context */
    libnet_plist_t *plist;          /* linked list of ports */
    u_short ttl;                    /* starting IP TTL */
    u_short sport;                  /* source port */
    u_short dport;                  /* ramping destination port */
    u_short id;                     /* firepack packet ID */
    u_short packet_size;            /* outgoing packet size */
    u_char xv;                      /* expiry vector */
    u_char flags;                   /* internal flags used by the program */
#define FW_RESOLVE      0x01        /* resolve IP addresses */
#define FW_STRICT_RFC   0x02        /* strict RFC 793 compliance */
#define FW_BOUND        0x04        /* bound scan */
#define FW_FINGERPRINT  0x08        /* fingerprint (TCP only) */
    int packet_offset;              /* IP packet offset */
    int protocol;                   /* firewalking protocol to use */
    int pcap_timeout;               /* packet capturing timeout */
    u_long gateway;                 /* gateway to probe */
    u_long metric;                  /* metric host */
    u_long seq;                     /* TCP sequence number used */
    libnet_ptag_t ip;               /* ip ptag */
    libnet_ptag_t udp;              /* udp ptag */
    libnet_ptag_t tcp;              /* tcp ptag */
    libnet_ptag_t icmp;             /* icmp ptag */
    struct sockaddr_in sin;         /* socket address structure */
    struct firepack_stats stats;    /* stats */
#define FW_ERRBUF_SIZE  0x100       /* 256 bytes */
    char errbuf[FW_ERRBUF_SIZE];    /* errors here */
};

/* initializes firewalk context */
int                                 /* 1 on success -1 or failure */
fw_init_context(
    struct firepack **,             /* firewalk context */
    char *
    );

/* initialize firewalk networking primitives */
int                                 /* 1 on success -1 or failure */
fw_init_net(
    struct firepack **,             /* firewalk context */
    char *,                         /* target gateway */
    char *,                         /* metric */
    char *                          /* port list or NULL */
    );

/* ramping/scanning driver */
int
firewalk(
    struct firepack **              /* firewalk context */
    );

/* build initial probe template */
int                                 /* 1 on success -1 or failure */
fw_packet_build_probe(
    struct firepack **              /* firewalk context */
    );

/* build UDP header */
int                                 /* 1 on success -1 or failure */
fw_packet_build_udp(
    struct firepack **              /* firewalk context */
    );

/* build TCP header */
int                                 /* 1 on success -1 or failure */
fw_packet_build_tcp(
    struct firepack **              /* firewalk context */
    );

/* build ICMP header */
int                                 /* 1 on success -1 or failure */
fw_packet_build_icmp(
    struct firepack **              /* firewalk context */
    );

/* capture packet from network */
int                                 /* -1 on failure or packet code */
fw_packet_capture(
    struct firepack **              /* firewalk context */
    );

/* sets libpcap BPF filter */
int                                 /* 1 on success -1 or failure */
fw_set_pcap_filter(
    char *,                         /* filter code to install */
    struct firepack **              /* firewalk context */
    );

/* injects packet to network */
int                                 /* 1 on success -1 or failure */
fw_packet_inject(
    struct firepack **              /* firewalk context */
    );

/* updates packet template */
int                                 /* 1 on success -1 or failure */
fw_packet_update_probe(
    struct firepack **,             /* firewalk context */
    u_short                         /* 0 for ramping cport for scanning */
    );

/* verifies a ramping response */
int                                 /* packet code */
fw_packet_verify_ramp(
    struct firepack **              /* firewalk context */
    );

/* verifies a scanning response */
int                                 /* packet code */
fw_packet_verify_scan(
    struct firepack **              /* firewalk context */
    );

/* writes info to the user */
void
fw_report(
    int,                            /* packet class */
    struct firepack **              /* firewalk context */
    );

/* looks up the ICMP unreachable code of a response */
char *                              /* unreachable code */
fw_get_unreach_code(
    struct firepack **              /* firewalk context */
    );

/* report statistics to the user */
void
fw_report_stats(
    struct firepack **              /* firewalk context */
    );

/* installs a new signal handler for a specified signal */
int                                 /* 1 on success -1 or failure */
catch_sig(
    int,                            /* signal to catch */
    void (*)()                      /* new signal handler */
    );

/* handles SIGINT from user */
void
catch_sigint(
    int                             /* unused */
    );

/* converts a string to an int within the bounds specified */
int
fw_str2int(
    register const char *,          /* value to convert */
    register const char *,          /* canonical definition */
    register int,                   /* minimum */
    register int);                  /* maximum */

/* coverts canonical protocol to integer representation */
int                                 /* -1 on failure or protocol */
fw_prot_select(
    char *                          /* protocol */
    );

/* shutdown firewalk */
void
fw_shutdown(
    struct firepack **              /* firewalk context */
    );

/* dump usage */
void
usage(
    u_char *                        /* argv[0] */
    );

#endif /* _FIREWALK_H */

/* EOF */
