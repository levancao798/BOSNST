#   Building Open Source Network Security Tools
#   Clutch Makefile - libdnet component sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

srcdir		= .

CC		= gcc -g
CFLAGS		= -O2 -D_BSD_SOURCE -Wall
LDFLAGS	        = -L/usr/local/lib
OBJECTS         = clutch.o
INCS		= -I/usr/local/include
LIBS		= -ldnet

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

all: clutch

clutch: $(OBJECTS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *~ *core* clutch

# EOF
