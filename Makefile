#!/usr/bin/make -f
#
all:
	apxs2 -i -a -c -Wl,-Wall -Wl,-lm -I. mod_querystring2cookie.c


