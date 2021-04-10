#   Building Open Source Network Security Tools
#   Vacuum Makefile - libsf component sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

srcdir		= .

CC		= gcc -g
CFLAGS		= -O2 -D_BSD_SOURCE -Wall
#LDFLAGS	= -L/path/to/libsf/library/if/needed
OBJECTS         = legerdemain.o
#INCS		= -I/path/to/libsf/library/if/needed
LIBS		= -lsf -lpcap -lnet

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

all: legerdemain

legerdemain: $(OBJECTS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *~ *core* legerdemain

# EOF
