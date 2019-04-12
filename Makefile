#/*
# * Redistribution and use in source and binary forms, with or without
# * modification, are permitted only as authorized by the OpenLDAP
# * Public License.
# *
# * A copy of this license is available in the file LICENSE in the
# * top-level directory of the distribution or, alternatively, at
# * <http://www.OpenLDAP.org/license.html>.
# */
#
# LDAP_SRC abs path is /usr/src/duo/ldap-duo/16.04/openldap-2.4.42+dfsg/
# this file fashioned from openldap-2.4.42+dfsg/contrib/slapd-modules/passwd/Makefile
#
LDAP_SRC = ../../..
LDAP_BUILD = $(LDAP_SRC)
LDAP_INC = -I$(LDAP_BUILD)/include -I$(LDAP_SRC)/include -I$(LDAP_SRC)/servers/slapd -I${LDAP_SRC}/contrib/slapd-modules/passwd/libduo
LDAP_LIB = $(LDAP_BUILD)/libraries/libldap_r/libldap_r.la $(LDAP_BUILD)/libraries/liblber/liblber.la
LIBTOOL = $(LDAP_BUILD)/libtool
CC = gcc
OPT = -g -O2 -Wall -fPIC
DEFS =
INCS = $(LDAP_INC)
LIBS = $(LDAP_LIB)

PROGRAMS = pw-duo.la pw-duo-test
LTVER = 0:0:0

prefix=/usr/local
exec_prefix=$(prefix)
ldap_subdir=/openldap

libdir=$(exec_prefix)/lib
libexecdir=$(exec_prefix)/libexec
moduledir = $(libexecdir)$(ldap_subdir)

.SUFFIXES: .c .o .lo

.c.lo:
	$(LIBTOOL) --mode=compile $(CC) $(OPT) $(DEFS) $(INCS) -c $<

all: $(PROGRAMS)

pw-duo.la:	pw-duo.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? -L./libduo/ -lduo -lssl -lcrypto

pw-duo-test: pw-duo.c
	gcc pw-duo-test.c -o pw-duo-test -L./libduo/ -I./libduo -lduo -lssl -lcrypto

clean:
	rm -rf *.o *.lo *.la .libs

install: $(PROGRAMS)
	mkdir -p $(DESTDIR)$(moduledir)
	for p in $(PROGRAMS) ; do \
		$(LIBTOOL) --mode=install cp $$p $(DESTDIR)$(moduledir) ; \
	done

