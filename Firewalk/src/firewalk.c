/*
 *  $Id: firewalk.c,v 1.2 2002/05/14 23:28:37 route Exp $
 *
 *  Firewalk 5.0
 *  firewalk.c - Scanning driver
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
firewalk(struct firepack **fp)
{
    int done, i, j;
    u_short bport, cport, eport;

    /* inform the user what's what */
    printf("%s-based scan.\n",
            (*fp)->protocol == IPPROTO_TCP ? "TCP" : "UDP");
    printf("Ramping phase source port: %d, destination port: %d\n",
            (*fp)->sport, (*fp)->dport);
    if ((*fp)->flags & FW_STRICT_RFC && (*fp)->protocol == IPPROTO_TCP)
    {
        printf("Using strict RFC adherence.\n");
    }
    printf("Hotfoot through %s using %s as a metric.\n",
            libnet_addr2name4(((*fp)->gateway),
            ((*fp)->flags) & FW_RESOLVE),
            libnet_addr2name4(((*fp)->metric),
            ((*fp)->flags) & FW_RESOLVE));

    /*
     *  PHASE ONE: Firewalk hopcount ramping
     *  A standard Traceroute-style IP expiry scan is initiated towards
     *  the metric, with the intent being to find how many hops away the
     *  target gateway is from the scanning host.  We'll increment the
     *  hopcounter and update packet template each pass through the loop.
     */
    printf("Ramping Phase:\n");
    for (done = 0, i = 0; !done && i < FW_IP_HOP_MAX; i++)
    {
        /* send a series of probes (currently only one) */
        for (j = 0; j < 1; j++)
        {
            fprintf(stderr, "%2d (TTL %2d): ", i + 1, (*fp)->ttl);
            if (fw_packet_inject(fp) == -1)
            {
                /*
                 *  Perhaps this write error was transient.  We'll hope
                 *  for the best.  Inform the user and continue.
                 */
                fprintf(stderr, "fw_packet_inject(): %s\n",
                        (*fp)->errbuf);
                continue;
            }
            switch (fw_packet_capture(fp))
            {
                case FW_PACKET_IS_UNREACH_EN_ROUTE:
                case FW_PACKET_IS_TTL_EX_EN_ROUTE:
                    if ((*fp)->flags & FW_BOUND)
                    {
                        printf("Binding host reached.\n");
                        done = 1;
                    }
                    break;
                case FW_PACKET_IS_TERMINAL_TTL_EX:
                case FW_PACKET_IS_TERMINAL_UNREACH:
                case FW_PACKET_IS_TERMINAL_SYNACK:
                case FW_PACKET_IS_TERMINAL_RST:
                    /* any terminal response will end phase one */
                    done = 1;
                    break;
                case -1:
                case FW_SERIOUS_ERROR:
                    /* err msg set in fw_packet_capture() */
                    return (FW_SERIOUS_ERROR);
                case FW_USER_INTERRUPT:
                    /* user hit ctrl-c */
                    return (FW_USER_INTERRUPT);
            }
        }
        if (!done)
        {
            if (fw_packet_update_probe(fp, 0) == -1)
            {
                /* error msg set in fw_packet_update_probe */
                return (-1);
            }
        }
    }
    if (done && !((*fp)->flags & FW_BOUND))
    {
        /*
         *  If we're "done" but not "bound" then we hit the metric
         *  before we hit the target gateway.  This means the target
         *  gateway is not en route to the metric.  Game's over kids.
         */
        sprintf((*fp)->errbuf, 
                "metric responded before target; must not be en route");
        return (FW_ABORT_SCAN);
    }
    if (!done)
    {
        /* if we fall through down here, we've exceeded our hopcount */
        sprintf((*fp)->errbuf, "hopcount exceeded");
        return (FW_ABORT_SCAN);
    }

    /*
     *  PHASE TWO: Firewalk scanning
     *  A series of probes are sent from to the metric with the bound IP
     *  TTL. If a given probe is accepted through the target gateway's
     *  ACL, we will receive an ICMP TTL expired in transit from the
     *  binding host If we receive no response after the timeout expires,
     *  it is assumed the probe violated the ACL on the target and was
     *  dropped.
     */
    (*fp)->ttl += (*fp)->xv;
    printf("Scan bound at %d hops.\n", (*fp)->ttl);
    printf("Scanning Phase: \n");
    for (done = 0, i = 0; !done; i++)
    {
        if (!libnet_plist_chain_next_pair((*fp)->plist, &bport, &eport))
        {
            /* we've exhausted our portlist and we're done */
            done = 1;
            continue;
        }
        while (!(bport > eport) && bport != 0)
        {
            cport = bport++;
            if (fw_packet_update_probe(fp, cport) == -1)
            {
                /* error msg set in fw_packet_update_probe */
                return (-1);
            }

            /* send a series of probes (currently only one) */
            for (j = 0; j < 1; j++)
            {
                fprintf(stderr, "port %3d: ", cport);
                (*fp)->stats.ports_total++;
                if (fw_packet_inject(fp) == -1)
                {
                    /*
                     *  Perhaps this write error was transient.  We'll
                     *  hope for the best.  Inform the user and continue.
                     */
                    fprintf(stderr, "fw_packet_inject(): %s\n",
                            (*fp)->errbuf);
                    continue;
                }
                /* we don't care what the return value is this time */
                switch(fw_packet_capture(fp))
                {
                    case FW_USER_INTERRUPT:
                        return (FW_USER_INTERRUPT);
                    case -1:
                    case FW_SERIOUS_ERROR:
                        /* err msg set in fw_packet_capture() */
                        return (FW_SERIOUS_ERROR);
                    default:
                        /* empty */
                }
            }
        }
    }
    return (1);
}

/* EOF */
