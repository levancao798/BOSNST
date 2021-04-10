/*
 *  $Id: report.c,v 1.4 2002/05/15 06:46:54 route Exp $
 *
 *  Firewalk 5.0
 *  report.c - Reporting code
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
#include "../include/unreachables.h"

void
fw_report(int class, struct firepack **fp)
{
    struct libnet_ipv4_hdr *ip_hdr;

    ip_hdr = (struct libnet_ipv4_hdr *)
            ((*fp)->packet + (*fp)->packet_offset);

    if (((*fp)->flags & FW_BOUND) &&
        ip_hdr->ip_src.s_addr == (*fp)->metric)
    {
        /* adjacent target gateway and metric */
        printf("A! ");
    }
    switch (class)
    {
        case FW_PACKET_IS_TTL_EX_EN_ROUTE:
            printf("expired [%s]\n",
                    libnet_addr2name4(ip_hdr->ip_src.s_addr, 
                    ((*fp)->flags) & FW_RESOLVE));
            break;
        case FW_PACKET_IS_UNREACH_EN_ROUTE:
            printf("unreach %s [%s]\n",
                    fw_get_unreach_code(fp),
                    libnet_addr2name4(ip_hdr->ip_src.s_addr,
                    ((*fp)->flags) & FW_RESOLVE));
            break;
        case FW_PACKET_IS_TERMINAL_TTL_EX:
            printf("terimnal (expired) [%s]\n",
                    libnet_addr2name4(ip_hdr->ip_src.s_addr,
                    ((*fp)->flags) & FW_RESOLVE));
            break;
        case FW_PACKET_IS_TERMINAL_UNREACH:
            printf("terminal (unreach %s) [%s]\n",
                    fw_get_unreach_code(fp),
                    libnet_addr2name4(ip_hdr->ip_src.s_addr,
                    ((*fp)->flags) & FW_RESOLVE));
            break;
        case FW_PACKET_IS_TERMINAL_SYNACK:
            printf("terminal (synack) [%s]\n",
                    libnet_addr2name4(ip_hdr->ip_src.s_addr,
                    ((*fp)->flags) & FW_RESOLVE));
            break;
        case FW_PACKET_IS_TERMINAL_RST:
            printf("terminal (rst) [%s]\n",
                    libnet_addr2name4(ip_hdr->ip_src.s_addr,
                    ((*fp)->flags) & FW_RESOLVE));
            break;
        case FW_PORT_IS_OPEN_SYNACK:
            printf("open (port listen) [%s]\n",
                    libnet_addr2name4(ip_hdr->ip_src.s_addr,
                    ((*fp)->flags) & FW_RESOLVE));
            (*fp)->stats.ports_open++;
            break;
        case FW_PORT_IS_OPEN_RST:
            printf("open (port not listen) [%s]\n",
                    libnet_addr2name4(ip_hdr->ip_src.s_addr,
                    ((*fp)->flags) & FW_RESOLVE));
            (*fp)->stats.ports_open++;
            break;
        case FW_PORT_IS_OPEN_UNREACH:
            printf("unknown (unreach %s) [%s]\n",
                    fw_get_unreach_code(fp),
                    libnet_addr2name4(ip_hdr->ip_src.s_addr,
                    ((*fp)->flags) & FW_RESOLVE));
            (*fp)->stats.ports_unknown++;
            break;
        case FW_PORT_IS_OPEN_TTL_EX:
            printf("open (expired) [%s]\n",
                    libnet_addr2name4(ip_hdr->ip_src.s_addr,
                    ((*fp)->flags) & FW_RESOLVE));
            (*fp)->stats.ports_open++;
            break;
        default:
            break;
    }
}


void
fw_report_stats(struct firepack **fp)
{
    printf("\nTotal packets sent:                %ld\n"
             "Total packet errors:               %ld\n"
             "Total packets caught               %ld\n"
             "Total packets caught of interest   %d\n"
             "Total ports scanned                %d\n"
             "Total ports open:                  %d\n"
             "Total ports unknown:               %d\n",
        (*fp)->stats.packets_sent, (*fp)->stats.packets_err,
        (*fp)->stats.packets_caught,
        (*fp)->stats.packets_caught_interesting,
        (*fp)->stats.ports_total, (*fp)->stats.ports_open,
        (*fp)->stats.ports_unknown);

}


char *
fw_get_unreach_code(struct firepack **fp)
{
    struct libnet_icmpv4_hdr *icmp_hdr;

    icmp_hdr = (struct libnet_icmpv4_hdr *)
            ((*fp)->packet + (*fp)->packet_offset + LIBNET_IPV4_H);
    if (icmp_hdr->icmp_code > 15)
    {
        return ("Unknown unreachable code");
    }
    return (unreachables[icmp_hdr->icmp_code]);
}

/* EOF */
