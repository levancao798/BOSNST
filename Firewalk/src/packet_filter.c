/*
 *  $Id: packet_filter.c,v 1.2 2002/05/14 00:17:52 route Exp $
 *
 *  Firewalk 5.0
 *  packet_filter.c - Packet filtering code
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
fw_set_pcap_filter(char *filter, struct firepack **fp)
{
    struct bpf_program filter_code;
    bpf_u_int32 local_net, netmask;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* get the subnet mask of the interface */
    if (pcap_lookupnet((*fp)->device, &local_net, &netmask, errbuf) == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "pcap_lookupnet(): %s",
                    errbuf);
        return (-1);
    } 

    /* compile the BPF filter code */
    if (pcap_compile((*fp)->p, &filter_code, filter, 1, netmask) == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "pcap_compile(): %s",
                pcap_geterr((*fp)->p));
        return (-1);
    }

    /* apply the filter to the interface */
    if (pcap_setfilter((*fp)->p, &filter_code) == -1)
    {
        snprintf((*fp)->errbuf, FW_ERRBUF_SIZE, "pcap_setfilter(): %s",
                pcap_geterr((*fp)->p));
        return (-1);
    }
    return (1);
}

/* EOF */
