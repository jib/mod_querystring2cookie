#!/usr/bin/make -f
#
all: check 

check:

install:
	apxs2 -i -a -c -Wl,-Wall -Wl,-lm -I$(top_srcdir)


