#   Building Open Source Network Security Tools
#   Roil Makefile - OpenSSL component sample code
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

srcdir		= .

CC		= gcc -g
CFLAGS		= -O2 -D_BSD_SOURCE -Wall
LDFLAGS         = -L/usr/local/ssl/lib
OBJECTS         = roil.o
INCS            = -I/usr/local/ssl/include
LIBS		= -lcrypto

.c.o:
	$(CC) -c $(CFLAGS) $(INCS) $<

all: roil

roil: $(OBJECTS)
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS) $(LDFLAGS) $(LIBS)

clean:
	rm -f *.o *~ *core* roil

# EOF
