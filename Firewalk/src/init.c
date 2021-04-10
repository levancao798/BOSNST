/*
 *  $Id: init.c,v 1.5 2002/05/15 06:46:54 route Exp $
 *
 *  Firewalk 5.0
 *  init.c - Main loop driver initialization
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
fw_init_context(struct firepack **fp, char *errbuf)
{
    *fp = (struct firepack *)malloc(sizeof(struct firepack));
    if (*fp == NULL)
    {
        snprintf(errbuf, FW_ERRBUF_SIZE, "malloc(): %s", strerror(errno));
        return (-1);
    }
    memset(*fp, 0, sizeof(struct firepack));

    /* set defaults here */
    (*fp)->ttl          = 1;       /* initial probe IP TTL */
    (*fp)->sport        = 53;      /* source port (TCP and UDP) */
    (*fp)->dport        = 33434;   /* ala traceroute */
    (*fp)->protocol     = IPPROTO_UDP;
    (*fp)->id           = getpid();
    (*fp)->pcap_timeout = FW_REPLY_TIMEOUT;
    (*fp)->xv           = 1;
    (*fp)->flags        |= FW_RESOLVE;

    /* setup our signal handler to handle a ctrl-c */
    if (catch_sig(SIGINT, catch_sigint) == -1)
    {
        snprintf(errbuf, FW_ERRBUF_SIZE, "catch_sig(): %s",
                strerror(errno));
        return (-1);
    }

    return (1);
}

int
fw_init_net(struct firepack **fp, char *gw, char *m, char *port_list)
{
#if HAVE_BPF
    int one;
#endif
    char errbuf[PCAP_ERRBUF_SIZE];

    /* get a libnet context */
    (*fp)->l = libnet_init(LIBNET_LINK, (*fp)->device, errbuf);
    if ((*fp)->l == NULL)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "libnet_init(): %s",
                errbuf);
        return (-1);
    }

    /* get our device if the user didn't specify one*/
    if ((*fp)->device == NULL)
    {
        (*fp)->device = libnet_getdevice((*fp)->l);
    }

    /* get the source address of our outgoing interface */
    (*fp)->sin.sin_addr.s_addr = libnet_get_ipaddr4((*fp)->l);

    /* setup the target gateway */
    if (((*fp)->gateway = libnet_name2addr4((*fp)->l, gw, 1)) == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE,
                "libnet_name2addr4(): %s (target gateway: %s)",
                libnet_geterror((*fp)->l), gw);
        return (-1);
    }

    /* setup the metric */
    if (((*fp)->metric = libnet_name2addr4((*fp)->l, m, 1)) == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE,
                "libnet_name2addr4(): %s (metric: %s)",
                libnet_geterror((*fp)->l), m);
        return (-1);
    }

    /* sanity check */
    if ((*fp)->gateway == (*fp)->metric)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE,
                "target gateway and metric cannot be the same");
        return (-1);
    }

    /* get our port list stuff situated */
    if (libnet_plist_chain_new((*fp)->l, &(*fp)->plist,
        port_list == NULL ? strdup(FW_DEFAULT_PORT_LIST) :
        port_list) == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE,
            "libnet_plist_chain_new(): %s\n", libnet_geterror((*fp)->l));
        return (-1);
    }

    /* get a pcap context */
    (*fp)->p = pcap_open_live((*fp)->device, FW_SNAPLEN, 0, 0, errbuf);
    if (((*fp)->p) == NULL)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "pcap_open_live(): %s",
                errbuf);
        return (-1);
    }

#if HAVE_BPF
    /*
     *  BPF, by default, will buffer packets inside the kernel until
     *  either the timer expires (which we do not use) or when the buffer
     *  fills up.  This is not sufficient for us since we could miss
     *  responses to our probes.  So we set BIOCIMMEDIATE to tell BPF
     *  to return immediately when it gets a packet.  This is pretty much
     *  the same behavior we see with Linux which returns every time it
     *  sees a packet.  This is less than efficient since we're spending
     *  more time interrupting the kernel, but hey, we gotta get our
     *  work done!
     */
    one = 1;
    if (ioctl(pcap_fileno((*fp)->p), BIOCIMMEDIATE, &one) < 0)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE,
                "ioctl(): BIOCIMMEDIATE: %s", strerror(errno));
        return (-1);
    }
#endif

    /* get the datalink size */
    switch (pcap_datalink((*fp)->p))
    {
        case DLT_SLIP:
            (*fp)->packet_offset = 0x10;
            break;
        case DLT_RAW:
            (*fp)->packet_offset = 0x00;
            break;             
        case DLT_PPP:
            (*fp)->packet_offset = 0x04;
            break;
        case DLT_EN10MB:
        default:
            (*fp)->packet_offset = 0x0e;
            break;
    }

    /*
     *  Set pcap filter and determine outgoing packet size.  The filter
     *  will be determined by the scanning protocol: 
     *  UDP scan:
     *  icmp[0] == 11 or icmp[0] == 3 or udp
     *  TCP scan:
     *  icmp[0] == 11 or icmp[0] == 3 or tcp[14] == 0x12 or tcp[14] \
     *  == 0x4 or tcp[14] == 0x14
     */
    switch ((*fp)->protocol)
    {
        case IPPROTO_UDP:
            if (fw_set_pcap_filter(FW_BPF_FILTER_UDP, fp) == -1)
            {
                /* err msg set in fw_set_pcap_filter() */
                return (-1);
            }
            /* IP + UDP */
            (*fp)->packet_size = LIBNET_IPV4_H + LIBNET_UDP_H;
            break;
        case IPPROTO_TCP:
            if (fw_set_pcap_filter(FW_BPF_FILTER_TCP, fp) == -1)
            {
                /* err msg set in fw_set_pcap_filter() */
                return (-1);
            }
            /* IP + TCP */
            (*fp)->packet_size = LIBNET_IPV4_H + LIBNET_TCP_H;

            /* randomize the TCP sequence number */
            libnet_seed_prand((*fp)->l);
            (*fp)->seq = libnet_get_prand(LIBNET_PRu32);
            break;
        default:
            sprintf((*fp)->errbuf,
                    "fw_init_network(): unsupported protocol");
            return (-1);
    }

    /*
     *  Build a probe packet template.  We'll use this packet template
     *  over and over for each write to the network, modifying certain
     *  fields (IP TTL, UDP/TCP ports and of course checksums as we go).
     */
    if (fw_packet_build_probe(fp) == -1)
    {
        /* error msg set in fw_packet_build_probe() */
        return (-1);
    }
    return (1);
}

void
fw_shutdown(struct firepack **fp)
{
    if (*fp)
    {
        if ((*fp)->p)
        {
            pcap_close((*fp)->p);
        }
        if ((*fp)->l)
        {
            libnet_destroy((*fp)->l);
        }
        if ((*fp)->plist)
        {
            libnet_plist_chain_free((*fp)->plist);
        }

        free(*fp);
        *fp = NULL;
    }
}

/* EOF */
