/*
 *  $Id: util.c,v 1.2 2002/05/14 00:17:52 route Exp $
 *
 *  Firewalk 5.0
 *  util.c - Misc routines
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
#include <stdarg.h>
#include "../include/firewalk.h"

int
fw_str2int(register const char *str, register const char *what,
    register int min, register int max)
{
    register const char *cp;
    register int val;
    char *ep;

    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
    {
        cp = str + 2;
        val = (int)strtol(cp, &ep, 16);
    }
    else
    {
        val = (int)strtol(str, &ep, 10);
    }

    if (*ep != '\0')
    {
        fprintf(stderr, "\"%s\" bad value for %s \n", str, what);
        exit(EXIT_FAILURE);
    }
    if (val < min && min >= 0)
    {
        if (min == 0)
        {
            fprintf(stderr, "%s must be >= %d\n", what, min);
            return (-1);
        }
        else
        {
            fprintf(stderr, "%s must be > %d\n", what, min - 1);
            exit(EXIT_FAILURE);
        }
    }
    if (val > max && max >= 0)
    {
        fprintf(stderr, "%s must be <= %d\n", what, max);
        exit(EXIT_FAILURE);
    }
    return (val);
}

int
fw_prot_select(char *protocol)
{
    char *supp_protocols[] = {"UDP", "TCP", 0};
    int i;

    for (i = 0; supp_protocols[i]; i++)
    {
        if ((!strcasecmp(supp_protocols[i], protocol)))
        {
            switch (i)
            {
                case 0:
                    /* UDP */
                    return (IPPROTO_UDP);
                case 1:
                    /* TCP */
                    return (IPPROTO_TCP);
                default:
                    fprintf(stderr, "unsupported protocol: %s\n",
                            protocol);
                    exit(EXIT_FAILURE);
            }
        }
    }
    fprintf(stderr, "unsupported protocol: %s\n", protocol);
    return (-1);
}

/* EOF */
