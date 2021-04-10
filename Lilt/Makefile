#   Building Open Source Network Security Tools
#   Lilt Makefile - libnids component sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

srcdir		= .

CC		= gcc -g
CFLAGS		= -O2 -Wall
# Make sure -lnet references the 1.0.x version of libnet.
#LDFLAGS	= -L/path/to/libnids/library/if/needed
OBJECTS         = lilt.o
#INCS		= -I/path/to/libnids/headers/if/needed
LIBS		= -lpcap -lnet -lnids

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

all: lilt

lilt: $(OBJECTS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *~ *core* lilt

# EOF
