#   Building Open Source Network Security Tools
#   Toplevel Makefile
#
#   Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
#   All rights reserved.

all: tools
#tools: stroke punch lilt legerdemain clutch roil scoop knock sift firewalk
tools: stroke punch legerdemain clutch roil scoop knock sift firewalk

stroke:
	(cd Stroke; make)

punch:
	(cd Punch; make)

lilt:
	(cd Lilt; make)

legerdemain:
	(cd Legerdemain; make)

clutch:
	(cd Clutch; make)

roil:
	(cd Roil; make)

scoop:
	(cd Scoop; make)

knock:
	(cd Knock; make)

descry:
	(cd Descry; make)

sift:
	(cd Sift; make)

firewalk:
	(cd Firewalk; ./configure && make)

clean:
	(cd Stroke; make clean)
	(cd Punch; make clean)
	(cd Lilt; make clean)
	(cd Legerdemain; make clean)
	(cd Clutch; make clean)
	(cd Roil; make clean)
	(cd Scoop; make clean)
	(cd Knock; make clean)
	(cd Sift; make clean)
	(cd Descry; make clean)
	(cd Firewalk; make distclean)

# EOF
