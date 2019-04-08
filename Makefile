# This file fashioned from openldap-2.4.42+dfsg/contrib/slapd-modules/passwd/Makefile
#
# 2019-03-22 - tmb384 (tmb384) - need the header files from a clean build of slapd so...
# 1) apt-get source slapd
# 2) xenial buildlog is here: https://launchpadlibrarian.net/321982631/buildlog_ubuntu-xenial-amd64.openldap_2.4.42+dfsg-2ubuntu3.2_BUILDING.txt.gz
# 3) export prefix="/usr/local/openldap-2.4.42-tmb"; dh_auto_configure -- --prefix=${prefix} --libexecdir='${prefix}/lib' --sysconfdir=/etc \
     --localstatedir=/var --mandir='${prefix}/share/man' --enable-debug --enable-dynamic --enable-syslog --enable-proctitle --enable-ipv6 \
     --enable-local --enable-slapd --enable-dynacl --enable-aci --enable-cleartext --enable-crypt --disable-lmpasswd --enable-spasswd \
     --enable-modules --enable-rewrite --enable-rlookups --enable-slapi --enable-slp --enable-wrappers --enable-backends=mod --disable-ndb \
     --enable-overlays=mod --with-subdir=ldap --with-cyrus-sasl --with-threads --with-gssapi --with-tls=gnutls --with-odbc=unixodbc  \
     --enable-memberof  --enable-ppolicy --enable-accesslog --enable-dynamic --disable-slapd  --enable-passwd

# LDAP_SRC abs path is /usr/src/duo/ldap-duo/16.04/openldap-2.4.42+dfsg/
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

pw-duo.la:      pw-duo.lo
        $(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
        -rpath $(moduledir) -module -o $@ $? -L./libduo/ -lduo -lssl -lcrypto

pw-duo-test: pw-duo.ck
        gcc pw-duo-test.c -o pw-duo-test -L./libduo/ -I./libduo -lduo -lssl -lcrypto

clean:
        rm -rf *.o *.lo *.la .libs

install: $(PROGRAMS)
        mkdir -p $(DESTDIR)$(moduledir)
        for p in $(PROGRAMS) ; do \
                $(LIBTOOL) --mode=install cp $$p $(DESTDIR)$(moduledir) ; \
        done
