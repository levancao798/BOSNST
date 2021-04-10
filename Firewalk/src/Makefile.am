# $Id: Makefile.am,v 1.3 2002/05/14 23:28:37 route Exp $
#
# Firewalk automake information file
# Copyright (c) 1998 - 2002 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
# Process this file with automake to produce a Makefile.in script.

include $(top_srcdir)/Makefile.am.common

sbin_PROGRAMS = firewalk

firewalk_SOURCES = 	init.c \
			firewalk.c \
			main.c \
			packet_build.c \
			packet_capture.c \
			packet_filter.c \
			packet_inject.c \
			packet_update.c \
			packet_verify.c \
			report.c \
			signal.c \
			util.c

all:
	cp firewalk $(top_srcdir)
	strip $(top_srcdir)/firewalk

clean:
	rm -f $(top_srcdir)/firewalk

distclean:
	rm -f $(top_srcdir)/firewalk


