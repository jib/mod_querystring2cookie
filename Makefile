#!/usr/bin/make -f
#
all:
	apxs2 -a -c -Wl,-Wall -Wl,-lm -I. -I/usr/include/apreq2 mod_querystring2cookie.c


