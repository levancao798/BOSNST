/*
 *  $Id: packet_capture.c,v 1.4 2002/05/14 23:28:37 route Exp $
 *
 *  Firewalk 5.0
 *  packet_capture.c - Packet capturing routines
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

int loop = 1;

int
fw_packet_capture(struct firepack **fp)
{
    int pcap_fd, c, timed_out;
    fd_set read_set;
    struct timeval timeout;
    struct pcap_pkthdr pc_hdr;

    timeout.tv_sec = (*fp)->pcap_timeout;
    timeout.tv_usec = 0;

    pcap_fd = pcap_fileno((*fp)->p);
    FD_ZERO(&read_set);
    FD_SET(pcap_fd, &read_set);

    for (timed_out = 0; !timed_out && loop; )
    {
        c = select(pcap_fd + 1, &read_set, 0, 0, &timeout);
        switch (c)
        {
            case -1:
                snprintf((*fp)->errbuf, FW_ERRBUF_SIZE,
                        "select() %s", strerror(errno));
                return (-1);
            case 0:
                timed_out = 1;
                continue;
            default:
                if (FD_ISSET(pcap_fd, &read_set) == 0)
                {
                    timed_out = 1;
                    continue;
                }
                /* fall through to read the packet */
        }
        (*fp)->packet = (u_char *)pcap_next((*fp)->p, &pc_hdr);
        if ((*fp)->packet == NULL)
        {
            /* no NULL packets please */
            continue;
        }
        (*fp)->stats.packets_caught++;

        /*
         *  Submit the packet for verification first based on scan type,
         *  If we're not bound, we're still in phase one and need to
         *  verify the ramping response.  If we are bound, we're in
         *  phase two and we need to verify the terminal response.
         *  Then process the response from the verification engine.
         *  Report to the user if necessary and update the packet
         *  statistics.
         */
        switch (!(((*fp)->flags) & FW_BOUND) ? fw_packet_verify_ramp(fp) :
                fw_packet_verify_scan(fp))
        {
            case FW_PACKET_IS_TTL_EX_EN_ROUTE:
                /* RAMPING: TTL expired en route to gateway (standard) */
                fw_report(FW_PACKET_IS_TTL_EX_EN_ROUTE, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PACKET_IS_TTL_EX_EN_ROUTE);
            case FW_PACKET_IS_UNREACH_EN_ROUTE:
                /* RAMPING: Unreachable en route to gateway (uncommon) */
                fw_report(FW_PACKET_IS_UNREACH_EN_ROUTE, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PACKET_IS_TTL_EX_EN_ROUTE);
            case FW_PACKET_IS_TERMINAL_TTL_EX:
                /* RAMPING: TTL expired at destination (rare) */
                fw_report(FW_PACKET_IS_TERMINAL_TTL_EX, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PACKET_IS_TERMINAL_TTL_EX);
            case FW_PACKET_IS_TERMINAL_UNREACH:
                /* RAMPING: Unreachable at destination (uncommon) */
                fw_report(FW_PACKET_IS_TERMINAL_UNREACH, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PACKET_IS_TERMINAL_UNREACH);
            case FW_PACKET_IS_TERMINAL_SYNACK:
                fw_report(FW_PACKET_IS_TERMINAL_SYNACK, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PACKET_IS_TERMINAL_SYNACK);
            case FW_PACKET_IS_TERMINAL_RST:
                fw_report(FW_PACKET_IS_TERMINAL_RST, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PACKET_IS_TERMINAL_RST);
            case FW_PORT_IS_OPEN_SYNACK:
                /* SCANNING: A response from an open TCP port */
                fw_report(FW_PORT_IS_OPEN_SYNACK, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PORT_IS_OPEN_SYNACK);
            case FW_PORT_IS_OPEN_RST:
                /* SCANNING: A response from a closed TCP port */
                fw_report(FW_PORT_IS_OPEN_RST, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PORT_IS_OPEN_RST);
            case FW_PORT_IS_OPEN_UNREACH:
                /* SCANNING: A port unreachable response */
                fw_report(FW_PORT_IS_OPEN_UNREACH, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PORT_IS_OPEN_UNREACH);
            case FW_PORT_IS_OPEN_TTL_EX:
                /* SCANNING: A TTL expired */
                fw_report(FW_PORT_IS_OPEN_TTL_EX, fp);
                (*fp)->stats.packets_caught_interesting++;
                return (FW_PORT_IS_OPEN_TTL_EX);
            case FW_PACKET_IS_BORING:
            default:
                continue;
        }
    }
    if (!loop)
    {
        return (FW_USER_INTERRUPT);
    }
    /*
     *  If we get here, the scan timed out.  We either dropped a packet
     *  somewhere or there is some filtering going on.
     */
    printf("*no response*\n");
    fflush(stdout);
    return (FW_NO_REPLY);
}

/* EOF */
