#!/usr/bin/make -f
#
all:
	apxs2 -a -c -Wl,-Wall -Wl,-lm -I. mod_querystring2cookie.c


