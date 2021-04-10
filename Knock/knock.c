/*
 *  $Id: knock.c,v 1.1.1.1 2002/03/13 21:01:12 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  knock.c - Port Scanning Technique example code
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
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
 *
 */
 
#include "./knock.h"

int loop = 1;

int
main(int argc, char **argv)
{
    int c;
    u_char flags, to;
    u_char scan_type, scan_subtype;
    char *device;
    struct knock_pack *kp;
    char errbuf[LIBNET_ERRBUF_SIZE], host[512], p_list[100];
 
    printf("Knock 1.0 [TCP / UDP port scanning tool]\n");

    to = 0;
    flags = 0;
    device = NULL;
    scan_type = SCAN_TCP;
    scan_subtype = SCAN_TCP_SYN;
    memset (&host, NULL, sizeof (host));
    while ((c = getopt(argc, argv, "hi:T:t:u")) != EOF)
    {
        switch (c)
        {
            case 'h':
                usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'i':
                device = optarg;
                break;
            case 'T':
                to = atoi(optarg);
                break;
            case 't':
                scan_type = SCAN_TCP;
                scan_subtype = atoi(optarg);
                switch (scan_subtype)
                {
                    case SCAN_TCP_SYN:
                        break;
                    case SCAN_TCP_FIN:
                        break;
                    case SCAN_TCP_XMAS:
                        break;
                    default:
                        usage(argv[0]);
                        exit(EXIT_FAILURE);
                }
                break;
            case 'u':
                scan_type = SCAN_UDP;
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    c = argc - optind;
    if (c != 2)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    else
    {
        /* target host */
        strncpy(host, argv[optind], sizeof (host) - 1);
        /* port list */
        strncpy(p_list, argv[optind + 1], sizeof (p_list) - 1);
    }

    /*
     *  Initialize knock.  Here we'll bring up libpcap and libnet.
     */
    kp = knock_init(device, flags, host, scan_type, scan_subtype, to, 
            p_list, errbuf);
    if (kp == NULL)
    {
        fprintf(stderr, "knock_init() failed: %s\n", errbuf);
        goto done;
    }

    /* print out the scan type */
    switch (scan_type)
    {
        case SCAN_UDP:
            printf("UDP");
            break;
        case SCAN_TCP:
            switch (scan_subtype)
            {
                case SCAN_TCP_SYN:
                    printf("TCP Half-open");
                    break;
                case SCAN_TCP_FIN:
                    printf("TCP Stealth FIN");
                    break;
                case SCAN_TCP_XMAS:
                    printf("TCP Stealth XMAS");
                    break;
            }
    }
    printf("-based port scan\n");
    printf("<ctrl-c> to quit\n");
    knock(kp);

done:
    if (kp)
    {
        printf("%d %s open\n", kp->ports_open, kp->ports_open == 1 ? 
                "port" : "ports");
    }
    knock_destroy(kp);
    /* shut down knock */
    return (EXIT_SUCCESS);
}


struct knock_pack *
knock_init(char *device, u_char flags, char *host, u_char scan_type,
            u_char scan_subtype, u_char to, char *p_list, char *errbuf)
{
    struct knock_pack *kp;

    /*
     *  We want to catch the interrupt signal so we can inform the user
     *  how many packets we captured before we exit.
     */
    if (catch_sig(SIGINT, cleanup) == -1)
    {
        sprintf(errbuf, "can't catch SIGINT signal.\n");
        return (NULL);
    }

    kp = malloc(sizeof (struct knock_pack));
    if (kp == NULL)
    {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, strerror(errno));
        return (NULL);
    }

    kp->flags = flags;
    kp->scan_type = scan_type;
    kp->scan_subtype = scan_subtype;
    kp->to = to == 0 ? NETWORK_TIMEOUT : to;

    /*
     *  If device is NULL, that means the user did not specify one and is
     *  leaving it up libpcap / libnet to find one.  We'll use libpcap's
     *  lookup routine, but they're both from the same codebase so it
     *  doesn't matter... ;)
     */
    if (device == NULL)
    {
        device = pcap_lookupdev(errbuf);
        if (device == NULL)
        {
            return (NULL);
        }
    }

    /*
     *  Open the packet capturing device with the following values:
     *
     *  SNAPLEN: We won't need more than 80 bytes
     *  PROMISC: on
     *  The interface needs to be in promiscuous mode to capture all
     *  network traffic on the localnet.
     *  TIMEOUT: 500ms
     *  A 500 ms timeout is probably fine for most networks.  For
     *  architectures that support it, you might want tune this value
     *  depending on how much traffic you're seeing on the network.
     */
    kp->p = pcap_open_live(device, SNAPLEN, PROMISC, TIMEOUT, errbuf);
    if (kp->p == NULL)
    {
        return (NULL);
    }

    /*
     *  We need to make sure this is Ethernet.  The DLTEN10MB specifies
     *  standard 10MB and higher Ethernet.
     */
    if (pcap_datalink(kp->p) != DLT_EN10MB)
    {
        sprintf(errbuf, "Knock only works with ethernet.\n");
        return (NULL);
    }

    kp->l = libnet_init(LIBNET_RAW4, device, errbuf);
    if (kp->l == NULL)
    {
        return (NULL);
    }

    kp->src_ip = libnet_get_ipaddr4(kp->l);

    if (!(kp->dst_ip = libnet_name2addr4(kp->l, host, LIBNET_RESOLVE)))
    {
        sprintf(errbuf, "libnet_name2addr4(): %s", 
                libnet_geterror(kp->l));
        return (NULL);
    }

    if (libnet_plist_chain_new(kp->l, &kp->plist, p_list) == -1)
    {
        sprintf(errbuf, "libnet_plist_chain_new(): %s", 
                libnet_geterror(kp->l));
        return (NULL);
    }
    return (kp);
}


void
knock_destroy(struct knock_pack *kp)
{
    if (kp)
    {
        if (kp->p)
        {
            pcap_close(kp->p);
        }
        if (kp->l)
        {
            libnet_destroy(kp->l);
        }
    }
} 


int
catch_sig(int signo, void (*handler)())
{
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(signo, &action, NULL) == -1)
    {
        return (-1);
    }
    else
    {
        return (1);
    }
}
 

void
knock(struct knock_pack *kp)
{
    u_short bport, eport;

    /*
     *  Loop until user hits ctrl-c at the command prompt or until we
     *  run out of ports to scan.
     */
    for (; loop; )
    {
        /* set ports */
        if (libnet_plist_chain_next_pair(kp->plist, &bport, &eport) < 1)
        {
            /* we're done */
            loop = 0;
            continue;
        }

        while (!(bport > eport) && bport != 0 && loop)
        {
            kp->port = bport++;

            /* build a port scanning packet */ 
            if (build_packet(kp) == -1)
            {
                fprintf(stderr, "build_packet: %s", kp->errbuf);
                continue;
            }

            /* write it the network */ 
            if (write_packet(kp) == -1)
            {
                fprintf(stderr, "write_packet: %s", kp->errbuf);
                continue;
            }
            fprintf(stderr, "port %d: ", kp->port);

            /* look for a response and report port status to user */
            switch (receive_packet(kp))
            {
                case PORT_OPEN:
                    printf("open\n");
                    kp->ports_open++;
                    break;
                case PORT_OPEN_TIMEDOUT:
                    printf("open? (timeout)\n");
                    kp->ports_open++;
                    break;
                case PORT_CLOSED:
                    printf("closed\n");
                    break;
                case PORT_CLOSED_TIMEDOUT:
                    printf("closed? (timeout)\n");
                    break;
            }
        }
    }
}


int
build_packet(struct knock_pack *kp)
{
    u_char control = 0;
    u_short protocol;
    u_long packet_size;

    /* determine total packet size and port scan type */
    packet_size = LIBNET_IPV4_H + (kp->scan_type == SCAN_TCP ?
            LIBNET_TCP_H : LIBNET_UDP_H);
    protocol = kp->scan_type == SCAN_TCP ? IPPROTO_TCP : IPPROTO_UDP;

    switch (kp->scan_type)
    {
        case SCAN_TCP:
            /* set the TCP scan type */
            switch (kp->scan_subtype)
            {
                case SCAN_TCP_SYN:
                    control = TH_SYN;
                    break;
                case SCAN_TCP_FIN:
                    control = TH_FIN;
                    break;
                case SCAN_TCP_XMAS:
                    control = TH_FIN | TH_URG | TH_PUSH;
                    break;
            }
            /*
             *  Build a TCP header.  If this is the first time we've hit
             *  this block of code, kp->tcpudp will be 0 and
             *  libnet_build_tcp() will create the state for the packet
             *  and we will save it to kp->tcpudp.  Each subsequent time
             *  we hit this block of code libnet_build_tcp will update
             *  this packet template.  This is the same for
             *  libnet_build_udp() and libnet_build_ip().
             */
            kp->tcpudp = libnet_build_tcp(
                SOURCE_PORT,                    /* source port */
                kp->port,                       /* destination port */
                0x00000bad,                     /* sequence number */
                0x0000bad0,                     /* acknowledgement num */
                control,                        /* control flags */
                32767,                          /* window size */   
                0,                              /* checksum */
                0,                              /* urgent pointer */
                LIBNET_TCP_H,                   /* TCP packet size */
                NULL,                           /* payload */  
                0,                              /* payload size */
                kp->l,                          /* libnet context */
                kp->tcpudp);                    /* libnet id */
            if (kp->tcpudp == -1)
            {
                sprintf(kp->errbuf, "Can't build TCP header: %s\n",
                        libnet_geterror(kp->l));
                return (-1);
            }
            break;
        case SCAN_UDP:
            kp->tcpudp = libnet_build_udp(
                SOURCE_PORT,                    /* source port */
                kp->port,                       /* destination port */
                LIBNET_UDP_H,                   /* packet size */
                0,                              /* checksum */
                NULL,                           /* payload */
                0,                              /* payload size */
                kp->l,                          /* libnet handle */
                kp->tcpudp);                    /* libnet id */
            if (kp->tcpudp == -1)
            {
                sprintf(kp->errbuf, "Can't build UDP header: %s\n",
                        libnet_geterror(kp->l));
                return (-1);
            }
            break;
    }

    kp->ip = libnet_build_ipv4(
        packet_size,                            /* total packet size */
        0,                                      /* type of service */
        242,                                    /* identification */
        0,                                      /* fragmentation */
        64,                                     /* time to live */
        protocol,                               /* protocol */
        0,                                      /* checksum */
        kp->src_ip,                             /* source */
        kp->dst_ip,                             /* destination */
        NULL,                                   /* payload */
        0,                                      /* payload size */
        kp->l,                                  /* libnet handle */
        kp->ip);                                /* ptag */
    if (kp->ip == -1)
    {
        sprintf(kp->errbuf, "Can't build IP header: %s\n",
                libnet_geterror(kp->l));
        return (-1);
    }

    return (1);
}


int
write_packet(struct knock_pack *kp)
{
    int c;

    c = libnet_write(kp->l);
    if (c == -1)
    {
        sprintf(kp->errbuf, "libnet_write(): %s\n",
                libnet_geterror(kp->l));
    }
    return (c);
}


int
receive_packet(struct knock_pack *kp)
{
    u_short ip_hl;
    time_t start;
    struct libnet_ipv4_hdr *ip;
    struct libnet_tcp_hdr *tcp;
    struct libnet_icmpv4_hdr *icmp;
    struct libnet_udp_hdr *udp;

    for (start = time(NULL); (time(NULL) - start) < kp->to; )
    {
        kp->packet = (u_char *)pcap_next(kp->p, &kp->h);
        if (kp->packet == NULL)
        {
            /*
             *  We have to be careful here as pcap_next() can return NULL
             *  if the timer expires with no data in the packet buffer or
             *  under some special circumstances under linux.
             */
            continue;
        }

        /*
         *  By using libnet's natively defined protocol headers, we can
         *  cast our received IP packet and access all header fields
         *  directly.  As you'll see, this is much easier than the bitwise
         *  stuff we had to do in the last chapter.  Also you'll note the
         *  lack of endian concern when dealing with libnet.  It handles 
         *  all of this for us.  How nice and thoughtful of libnet.
         */ 
        ip = (struct libnet_ipv4_hdr *)(kp->packet + 14);
        ip_hl = ip->ip_hl << 2;

        switch (ip->ip_p)
        {
            case IPPROTO_TCP:
                if (kp->scan_type != SCAN_TCP)
                {
                    continue;
                }

                tcp = (struct libnet_tcp_hdr *)(kp->packet + 14 + ip_hl);
                if (ip->ip_src.s_addr == kp->dst_ip && ip->ip_dst.s_addr
                    == kp->src_ip && ntohs(tcp->th_sport) == kp->port &&
                    ntohs(tcp->th_dport) == SOURCE_PORT)
                {
                    if ((tcp->th_flags & TH_SYN) && 
                        (tcp->th_flags & TH_ACK))
                    {
                        /* we got a SYN|ACK back, we know port is open */
                        return (PORT_OPEN);
                    }
                    if (tcp->th_flags & TH_RST)
                    {
                        /* we got an RST back, we know port is closed */
                        return (PORT_CLOSED);
                    }
                }
                continue;
            case IPPROTO_ICMP:
                if (kp->scan_type != SCAN_UDP)
                {
                    continue;
                }
                icmp = (struct libnet_icmpv4_hdr *)
                        (kp->packet + 14 + ip_hl);
                if (icmp->icmp_type != ICMP_UNREACH &&
                    icmp->icmp_code != ICMP_UNREACH_PORT)
                {
                    /* it's not a terminal response to our packet */
                    continue;
                }

                /* past IPv4 header, past ICMPv4 header */
                ip = (struct libnet_ipv4_hdr *)(kp->packet + 14
                        + ip_hl + LIBNET_ICMPV4_UNREACH_H);

                /* past IPv4 header, past ICMPv4 header, past IPv4 */
                udp = (struct libnet_udp_hdr *)(kp->packet + 14
                        + ip_hl + LIBNET_ICMPV4_UNREACH_H + 
                        LIBNET_IPV4_H);

                if (ip->ip_src.s_addr == kp->src_ip && ip->ip_dst.s_addr
                    == kp->dst_ip && ntohs(udp->uh_dport) == kp->port &&
                    ntohs(udp->uh_sport) == SOURCE_PORT)
                {
                    /* we got an ICMP port unreach; port is closed */
                    return (PORT_CLOSED);
                }
            default:
                continue;
        }
    }
    /*
     *  If we get down here, the scan has timed out, and depending on the
     *  scan protocol and type, the port may be open or it may be closed.
     */
    if (kp->scan_type == SCAN_TCP)
    {
        switch (kp->scan_subtype)
        {
            case SCAN_TCP_SYN:
                /* for half-open TCP scans assume the port is closed */
                return (PORT_CLOSED_TIMEDOUT);
            case SCAN_TCP_FIN:
            case SCAN_TCP_XMAS:
                /* for "stealth" TCP scans assume the port is open */
                return (PORT_OPEN_TIMEDOUT);
        }
    }
    else
    {
        /* for UDP scans assume the port is open */
        return (PORT_OPEN_TIMEDOUT);
    }
    /* NOTREACHED (this silences compiler warnings) */
    return (PORT_CLOSED);
}


void
cleanup(int signo)
{
    loop = 0;
    printf("Interrupt signal caught...\n");
}


void
usage(char *name)
{
    printf("usage %s [options] target_host port_list\n"
                    "-h\t\tthis blurb you see right here\n"
                    "-i device\tspecify a device\n"
                    "-T timeout\tseconds to wait for a resonse\n"
                    "-t scantype\tscan TCP ports "
                    "(1 == TCP SYN, 2 == TCP FIN, 3 == TCP XMAS)\n"
                    "-u\t\tscan UDP ports\n", name);
}


/* EOF */
