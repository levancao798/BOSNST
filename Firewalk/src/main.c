/*
 *  $Id: main.c,v 1.6 2002/05/15 06:46:54 route Exp $
 *
 *  Firewalk 5.0
 *  main.c - Main control logic
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
#include "../version.h"

int
main(int argc, char *argv[])
{
    int c;
    struct firepack *fp;
    char *port_list = NULL;
    char errbuf[FW_ERRBUF_SIZE];

    printf("Firewalk 5.0 [gateway ACL scanner]\n");

    /*
     *  Initialize the main control context.  We keep all of our
     *  program state here and this is used by just about every
     *  function in the program.
     */
    if (fw_init_context(&fp, errbuf) == -1)
    {
        fprintf(stderr, "fw_init_control(): %s\n", errbuf);
        goto done;
    }

    /* process commandline arguments */
    while ((c = getopt(argc, argv, "d:fhi:no:p:rS:s:T:t:vx:")) != EOF)
    {
        switch (c)
        {
            case 'd':
                /* destination port to use during ramping phase */
                fp->dport = fw_str2int(optarg, "ramping destination port",
                        FW_PORT_MIN, FW_PORT_MAX);
                break;                
            case 'f':
                /* stack fingerprint of each host */
                fp->flags |= FW_FINGERPRINT;
                break;
            case 'h':
                /* program help */
                usage(argv[0]);
                break;
            case 'i':
                /* interface */
                fp->device = optarg;
                break;
            case 'n':
                /* do not use names */
                fp->flags &= ~FW_RESOLVE;
                break;
            case 'p':
                /* select firewalk protocol */
                fp->protocol = fw_prot_select(optarg);
                break;
            case 'r':
                /* Strict RFC adherence */
                fp->flags |= FW_STRICT_RFC;
                break;
            case 'S':
                /* scan these ports */
                port_list = optarg;
                break;
            case 's':
                /* source port */
                fp->sport = fw_str2int(optarg, "source port",
                        FW_PORT_MIN, FW_PORT_MAX);
                break;
            case 'T':
                /* time to wait for packets from other end */
                    fp->pcap_timeout = fw_str2int(optarg, "read timer",
                        FW_PCAP_TIMEOUT_MIN, FW_PCAP_TIMEOUT_MAX);
                break;
            case 't':
                /* set initial IP TTL */
                fp->ttl = fw_str2int(optarg, "initial TTL",
                        FW_IP_HOP_MIN, FW_IP_HOP_MAX);
                break;
            case 'v':
                /* version */
                printf(FW_BANNER "version : %s\n", VERSION);
                goto done;
            case 'x':
                /* expire vector */
                fp->xv = fw_str2int(optarg, "expire vector",
                        FW_XV_MIN, FW_XV_MAX);
                break;
            default:
                usage(argv[0]);
        }
    }

    c = argc - optind;
    if (c != 2)
    {
        /*
         *  We should only have two arguments at this point, the target
         *  gateway and the metric.
         */
        usage(argv[0]);
    }
    
    /* initialize the network components */
    if (fw_init_net(&fp, argv[optind], argv[optind + 1], port_list) == -1)
    {
        fprintf(stderr, "fw_init_network(): %s\n", fp->errbuf);
        goto done;
    }
    printf("Firewalk state initialization completed successfully.\n");

    /* execute scan: phase one, and hopefully phase two */
    switch (firewalk(&fp))
    {
        case -1:
        case FW_SERIOUS_ERROR:
            /* grievous error of some sort */
            fprintf(stderr, "firewalk(): %s\n", fp->errbuf);
            break;
        case FW_ABORT_SCAN:
            /* hop count exceeded or metric en route */
            fprintf(stderr, "Scan aborted: %s.\n", fp->errbuf);
            break;
        case FW_USER_INTERRUPT:
            fprintf(stderr, "Scan aborted by user.\n");
            break;
        default:
            printf("\nScan completed successfully.\n");
            break;
    }
done:
    fw_report_stats(&fp);
    fw_shutdown(&fp);
    /* we should probably record proper exit status */
    return (EXIT_SUCCESS);
}

void
usage(u_char *argv0)
{
    fprintf(stderr, "Usage : %s [options] target_gateway metric\n"
        "\t\t   [-d %d - %d] destination port to use (ramping phase)\n"
        "\t\t   [-h] program help\n"
        "\t\t   [-i device] interface\n"
        "\t\t   [-n] do not resolve IP addresses into hostnames\n"
        "\t\t   [-p TCP | UDP] firewalk protocol\n"
        "\t\t   [-r] strict RFC adherence\n"
        "\t\t   [-S x - y, z] port range to scan\n"
        "\t\t   [-s %d - %d] source port\n"
        "\t\t   [-T 1 - 1000] packet read timeout in ms\n"
        "\t\t   [-t 1 - %d] IP time to live\n"
        "\t\t   [-v] program version\n"
        "\t\t   [-x 1 - %d] expire vector\n"
        "\n",   argv0, FW_PORT_MIN, FW_PORT_MAX, FW_PORT_MIN, FW_PORT_MAX,
                FW_IP_HOP_MAX, FW_XV_MAX);
        exit(EXIT_SUCCESS);
}

/* EOF */
