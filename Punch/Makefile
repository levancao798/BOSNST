#   Building Open Source Network Security Tools
#   Punch Makefile - libnet 1.1.0 component sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

srcdir		= .

CC		= gcc -g
CFLAGS		= -O2 -Wall
#LDFLAGS	= -L/path/to/libnet/library/if/needed
OBJECTS         = punch.o
#INCS		= -I/path/to/libnet/headers/if/needed
LIBS		= -lnet

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

all: punch

punch: $(OBJECTS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *~ *core* punch

# EOF
