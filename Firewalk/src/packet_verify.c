/*
 *  $Id: packet_verify.c,v 1.3 2002/05/14 20:20:39 route Exp $
 *
 *  Firewalk 5.0
 *  packet_verify.c - Packet verification code
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
fw_packet_verify_ramp(struct firepack **fp)
{
    struct libnet_ipv4_hdr *ip_hdr;
    struct libnet_icmpv4_hdr *icmp_hdr;
    struct libnet_ipv4_hdr *o_ip_hdr;
    struct libnet_tcp_hdr *tcp_hdr;

    /* point to the IP header */
    ip_hdr = (struct libnet_ipv4_hdr *)
            ((*fp)->packet + (*fp)->packet_offset);

    if (ip_hdr->ip_src.s_addr == (*fp)->sin.sin_addr.s_addr)
    {
        /* packets we send are of no interest to us here. */
        return (FW_PACKET_IS_BORING);
    }

    switch (ip_hdr->ip_p)
    {
        case IPPROTO_ICMP:
            icmp_hdr = (struct libnet_icmpv4_hdr *)
                ((*fp)->packet + (*fp)->packet_offset + LIBNET_IPV4_H);

            switch (icmp_hdr->icmp_type)
            {
                case ICMP_TIMXCEED:
                    if (icmp_hdr->icmp_code != ICMP_TIMXCEED_INTRANS)
                    {
                        /*
                         *  Packet was from an expired IP frag queue
                         *  reassembly timer.  Nothing we want.
                         */
                        break;
                    }
                case ICMP_UNREACH:
                    /*
                     *  Point to the original IPv4 header inside the ICMP
                     *  message's payload.  An IPv4 header is
                     *  LIBNET_IPV4_H bytes long and both ICMP unreachable
                     *  and time exeeed headers are 8 bytes.
                     */
                    o_ip_hdr = (struct libnet_ipv4_hdr *)
                            ((*fp)->packet + (*fp)->packet_offset
                            + LIBNET_IPV4_H + 8);

                    /*
                     *  Check the IP header of the packet that caused the
                     *  unreachable for our markings which include:
                     *  Original IP ID: set to the process id.
                     *  Original IP source address: our source address.
                     */
                    if (!FW_IS_OURS(o_ip_hdr, fp))
                    {
                        break;
                    }
                    if (ip_hdr->ip_src.s_addr == (*fp)->metric)
                    {
                        /*
                         *  ICMP response from our metric.  This ends
                         *  our scan since we've reached the metric
                         *  before the target gateway.
                         */
                        return ((icmp_hdr->icmp_type == ICMP_TIMXCEED) ?
                                FW_PACKET_IS_TERMINAL_TTL_EX :
                                FW_PACKET_IS_TERMINAL_UNREACH);
                    }
                    if (ip_hdr->ip_src.s_addr == (*fp)->gateway)
                    {
                        /*
                         *  Response from our target gateway.
                         */
                        (*fp)->flags |= FW_BOUND;
                    }
                    /*
                     *  If we get to this point, the packet is an
                     *  ICMP response from an intermediate router.
                     */
                    return ((icmp_hdr->icmp_type == ICMP_TIMXCEED) ?
                            FW_PACKET_IS_TTL_EX_EN_ROUTE :
                            FW_PACKET_IS_UNREACH_EN_ROUTE);
                    break;
                default:
                    break;
            }
        case IPPROTO_TCP:
            if ((*fp)->protocol != IPPROTO_TCP)
            {
                /*
                 *  We're only interested in TCP packets if this is a
                 *  TCP-based scan.
                 */
                break;
            }

            tcp_hdr = (struct libnet_tcp_hdr *)
                    ((*fp)->packet +
                    (*fp)->packet_offset + LIBNET_IPV4_H);

            if (!(tcp_hdr->th_flags & TH_SYN) &&
                !(tcp_hdr->th_flags & TH_RST))
            {
                /*
                 *  We only care about SYN|ACK and RST|ACK packets.
                 *  The rest can burn.
                 */
                break;
            }

            if ((*fp)->flags & FW_STRICT_RFC)
            {
                /*
                 *  Strict RFC compliance dictates that an RST or
                 *  an SYN|ACK will have our SEQ + 1 as the ACK number
                 *  also, the RST will have the ACK bit set).  This is of 
                 *  course, assuming the packet is ours.
                 */
                if (ntohl(tcp_hdr->th_ack) != (*fp)->seq + 1)
                {
                    break;
                }
            }

            if (ntohs(tcp_hdr->th_dport) == (*fp)->sport &&
                    ntohs(tcp_hdr->th_sport) == (*fp)->dport)
            {
                /* this is most likely a response to our SYN probe */
                return (((tcp_hdr->th_flags & TH_SYN) ?
                        FW_PACKET_IS_TERMINAL_SYNACK :
                        FW_PACKET_IS_TERMINAL_RST));
            }
            break;
    }
    return (FW_PACKET_IS_BORING);
}

int
fw_packet_verify_scan(struct firepack **fp)
{
    struct libnet_ipv4_hdr *ip_hdr;
    struct libnet_icmpv4_hdr *icmp_hdr;
    struct libnet_ipv4_hdr *o_ip_hdr;
    struct libnet_tcp_hdr *tcp_hdr;

    ip_hdr = (struct libnet_ipv4_hdr *)((*fp)->packet +
            (*fp)->packet_offset);

    if (ip_hdr->ip_src.s_addr == (*fp)->sin.sin_addr.s_addr)
    {
        /* packets we send are of no interest to us here. */
        return (FW_PACKET_IS_BORING);
    }
    switch (ip_hdr->ip_p)
    {
        case IPPROTO_ICMP:
            icmp_hdr = (struct libnet_icmpv4_hdr *)
                    ((*fp)->packet + (*fp)->packet_offset + LIBNET_IPV4_H);

            switch (icmp_hdr->icmp_type)
            {
                case ICMP_TIMXCEED:
                    if (icmp_hdr->icmp_code != ICMP_TIMXCEED_INTRANS)
                    {
                        /*
                         *  Packet was from an expired IP frag queue
                         *  reassembly timer.  Nothing we want.
                         */
                        break;
                    }
                case ICMP_UNREACH:
                    /*
                     *  Point to the original IPv4 header inside the ICMP
                     *  message's payload.  An IPv4 header is
                     *  LIBNET_IPV4_H bytes long and both ICMP unreachable
                     *  and time exeeed headers are 8 bytes.
                     */
                    o_ip_hdr = (struct libnet_ipv4_hdr *)
                            ((*fp)->packet + (*fp)->packet_offset
                            + LIBNET_IPV4_H + 8);

                    /*
                     *  Check the IP header of the packet that caused the
                     *  unreachable for our markings which include:
                     *  Original IP ID: set to the process id.
                     *  Original IP source address: our source address.
                     */
                    if (FW_IS_OURS(o_ip_hdr, fp))
                    {
                        /* the packet made it through the filter */
                        return ((icmp_hdr->icmp_type == ICMP_TIMXCEED) ?
                                FW_PORT_IS_OPEN_TTL_EX :
                                FW_PORT_IS_OPEN_UNREACH);
                    }
                    break;
                default:
                    break;
        }
        case IPPROTO_TCP:
            if ((*fp)->protocol != IPPROTO_TCP)
            {
                /*
                 *  We're only interested in TCP packets if this is a
                 *  TCP-based scan.
                 */
                break;
            }
            tcp_hdr = (struct libnet_tcp_hdr *)
                    ((*fp)->packet +
                    (*fp)->packet_offset + LIBNET_IPV4_H);

            /*
             *  We only care about SYN|ACK and RST|ACK packets.
             *  The rest can burn.
             */
            if (!(tcp_hdr->th_flags & TH_SYN) &&
                !(tcp_hdr->th_flags & TH_RST))
            {
                break;
            }

            if ((*fp)->flags & FW_STRICT_RFC)
            {
                /*
                 *  Strict RFC compliance dictates that an RST or
                 *  an SYN|ACK will have our SEQ + 1 as the ACK number
                 *  also, the RST will have the ACK bit set).  This is of 
                 *  course, assuming the packet is ours.
                 */
                if (ntohl(tcp_hdr->th_ack) != (*fp)->seq + 1)
                {
                    break;
                }
            }

            if (ntohs(tcp_hdr->th_dport) == (*fp)->sport &&
                    ntohs(tcp_hdr->th_sport) == (*fp)->dport)
            {
                /* the packet made it through the filter */
                return (((tcp_hdr->th_flags & TH_SYN) ?
                        FW_PORT_IS_OPEN_SYNACK :
                        FW_PORT_IS_OPEN_RST));
            }
            break;
        default:
            break;
    }
    return (FW_PACKET_IS_BORING);
}

/* EOF */
