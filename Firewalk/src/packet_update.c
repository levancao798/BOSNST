/*
 *  $Id: packet_update.c,v 1.3 2002/05/15 06:46:54 route Exp $
 *
 *  Firewalk 5.0
 *  packet_update.c - Packet updating code
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

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#include "../include/firewalk.h"

int
fw_packet_update_probe(struct firepack **fp, u_short cport)
{
    if (!((*fp)->flags & FW_BOUND))
    {
        /* phase one: just update IP TTL */
        (*fp)->ttl++;
    }
    else
    {
        /* phase two; update port scanning probe */
        switch ((*fp)->protocol)
        {
            case IPPROTO_TCP:
                (*fp)->dport = cport;

                (*fp)->tcp = libnet_build_tcp(
                    (*fp)->sport,                   /* source TCP port */
                    (*fp)->dport,                   /* dest TCP port */
                    (*fp)->seq,                     /* sequence number */
                    0L,                             /* ACK number */
                    TH_SYN,                         /* control flags */
                    1024,                           /* window size */
                    0,                              /* checksum */
                    0,                              /* urgent */
                    (*fp)->packet_size - LIBNET_IPV4_H, /* packet size */
                    NULL,                           /* payload */
                    0,                              /* payload size */
                    (*fp)->l,                       /* libnet context */
                    (*fp)->tcp);                    /* TCP ptag */
     
                if ((*fp)->tcp == -1)
                {       
                    snprintf((*fp)->errbuf, FW_ERRBUF_SIZE,
                        "libnet_build_tcp() %s",
                        libnet_geterror((*fp)->l));
                    return (-1);
                }
                break;
            case IPPROTO_UDP:
                (*fp)->dport = cport;

                (*fp)->udp = libnet_build_udp(
                    (*fp)->sport,                   /* source UDP port */
                    (*fp)->dport,                   /* dest UDP port */
                    (*fp)->packet_size - LIBNET_IPV4_H, /* size */
                    0,                              /* checksum */   
                    NULL,                           /* payload */
                    0,                              /* payload size */
                    (*fp)->l,                       /* libnet context */
                    (*fp)->udp);                    /* udp ptag */
     
                if ((*fp)->udp == -1)
                {       
                    snprintf((*fp)->errbuf, FW_ERRBUF_SIZE,
                        "libnet_build_udp() %s",
                        libnet_geterror((*fp)->l));
                    return (-1);
                }
                break;
        }
    }

    (*fp)->ip = libnet_build_ipv4(
            (*fp)->packet_size,                 /* packetlength */
            0,                                  /* IP tos */
            (*fp)->id,                          /* IP id */
            0,                                  /* IP frag bits */
            (*fp)->ttl,                         /* IP time to live */
            (*fp)->protocol,                    /* transport protocol */
            0,                                  /* checksum */
            (*fp)->sin.sin_addr.s_addr,         /* IP source */
            (*fp)->metric,                      /* IP destination */
            NULL,                               /* IP payload */
            0,                                  /* IP payload size */
            (*fp)->l,                           /* libnet context */
            (*fp)->ip);                         /* ip ptag */
 
    if ((*fp)->ip == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "libnet_build_ipv4() %s",
                libnet_geterror((*fp)->l));
        return (-1);
    }

    return (1);
}

/* EOF */
