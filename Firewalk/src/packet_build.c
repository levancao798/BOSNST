/*
 *  $Id: packet_build.c,v 1.2 2002/05/14 00:17:52 route Exp $
 *
 *  Firewalk 5.0
 *  packet_build.c - Packet construction code
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
fw_packet_build_probe(struct firepack **fp)
{
    arp_t *a;
    route_t *r;
    struct arp_entry arp;
    struct route_entry route;

    /* first build our transport layer header */
    switch ((*fp)->protocol)
    {
        case IPPROTO_UDP:
            if (fw_packet_build_udp(fp) == -1)
            {
                /* error msg set in fw_packet_build_udp() */
                return (-1);
            }
            break;
        case IPPROTO_TCP:
            if (fw_packet_build_tcp(fp) == -1)
            {
                /* error msg set in fw_packet_build_tcp() */
                return (-1);
            }
            break;
        default:
            sprintf((*fp)->errbuf,
                    "fw_packet_build_probe(): unknown protocol");
            return (-1);
    }

    /* build our IPv4 header */
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
            0);                                 /* No saved ptag */

    if ((*fp)->ip == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "libnet_build_ipv4() %s",
                libnet_geterror((*fp)->l));
        return (-1);
    }


    /*
     *  Now we need to get the MAC address of our first hop gateway.
     *  Dnet to the rescue!  We start by doing a route table lookup
     *  to determine the IP address we use to get to the
     *  destination host (the metric).
     */
    r = route_open();
    if (r == NULL)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "route_open()");
        route_close(r);
        return (-1);
    }

    /* convert the metric address to dnet's native addr_t format */
    if (addr_aton(libnet_addr2name4((*fp)->metric, 0),
            &route.route_dst) < 0)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "addr_aton()");
        route_close(r);
        return (-1);
    }
    /* get the route entry telling us how to reach the metric */
    if (route_get(r, &route) < 0)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "route_get()");
        route_close(r);
        return (-1);
    }
    route_close(r);

    a = arp_open();
    if (a == NULL)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "arp_open()");
        return (-1);        
    }
    /* get the MAC of the first hop gateway */
    arp.arp_pa = route.route_gw;
    if (arp_get(a, &arp) < 0)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "route_get()");
        arp_close(a);
        return (-1);
    }
    arp_close(a);

    /* build our ethernet header */
    if (libnet_autobuild_ethernet(
            (u_char *)&arp.arp_ha.addr_eth,
            ETHERTYPE_IP,
            (*fp)->l) == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE,
                "libnet_autobuild_ethernet() %s",
                libnet_geterror((*fp)->l));
        arp_close(a);
        return (-1);
    }

    return (1);
}

int
fw_packet_build_udp(struct firepack **fp)
{
    /* build a UDP header */
    (*fp)->udp = libnet_build_udp(
            (*fp)->sport,                       /* source UDP port */
            (*fp)->dport,                       /* dest UDP port */
            (*fp)->packet_size - LIBNET_IPV4_H, /* UDP size */
            0,                                  /* checksum */
            NULL,                               /* IP payload */
            0,                                  /* IP payload size */
            (*fp)->l,                           /* libnet context */
            0);                                 /* No saved ptag */

    if ((*fp)->udp == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "libnet_build_udp() %s",
                libnet_geterror((*fp)->l));
        return (-1);
    }
    return (1);
}

int
fw_packet_build_tcp(struct firepack **fp)
{
    /* build a TCP header */
    (*fp)->tcp = libnet_build_tcp(
            (*fp)->sport,                       /* source TCP port */
            (*fp)->dport,                       /* dest TCP port */
            (*fp)->seq,                         /* sequence number */
            0L,                                 /* ACK number */
            TH_SYN,                             /* control flags */
            1024,                               /* window size */
            0,                                  /* checksum */
            0,                                  /* urgent */
            (*fp)->packet_size - LIBNET_IPV4_H, /* TCP size */
            NULL,                               /* IP payload */
            0,                                  /* IP payload size */
            (*fp)->l,                           /* libnet context */
            0);                                 /* No saved ptag */

    if ((*fp)->tcp == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "libnet_build_tcp() %s",
                libnet_geterror((*fp)->l));
        return (-1);
    }
    return (1);
}


/* EOF */
