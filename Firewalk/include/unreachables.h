/*
 *  $Id: unreachables.h,v 1.2 2002/05/14 23:28:37 route Exp $
 *
 *  Firewalk 5.0
 *  unreachables.h - ICMP unreachable codes
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

#ifndef _FW_UNREACHABLES_H
#define _FW_UNREACHABLES_H

char *unreachables[] =
{
    "ICMP_UNREACH_NET",
    "ICMP_UNREACH_HOST",
    "ICMP_UNREACH_PROTOCOL",
    "ICMP_UNREACH_PORT",
    "ICMP_UNREACH_NEEDFRAG",
    "ICMP_UNREACH_SRCFAIL",
    "ICMP_UNREACH_NET_UNKNOWN",
    "ICMP_UNREACH_HOST_UNKNOWN",
    "ICMP_UNREACH_ISOLATED",
    "ICMP_UNREACH_NET_PROHIB",
    "ICMP_UNREACH_HOST_PROHIB",
    "ICMP_UNREACH_TOSNET",
    "ICMP_UNREACH_TOSHOST",
    "ICMP_UNREACH_FILTER_PROHIB",
    "ICMP_UNREACH_HOST_PRECEDENCE",
    "ICMP_UNREACH_PRECEDENCE_CUTOFF",
    0
};

#endif /* _FW_UNREACHABLES_H */

/* EOF */
