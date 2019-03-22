# $OpenLDAP$
# CPPFLAGS+=-Iopenldap-2.4.31/include -Ifreeradius-client-1.1.6/include/ -fPIC -Wall
# 2016-01-05 tmb -i can't compile radexample unless freeradius-1.1.6 source is included
#
# 2016-01-05 - tmb - with 14.04, we can use ubuntu libfreeradius-client-dev package and no need
# to download source. Can't compile radexampel however because it needs config.h from source
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
#
#    make depend
#
CPPFLAGS+=-I../openldap-2.4.42+dfsg/include -shared -fPIC -dPIC -Wall

CC=gcc
LIBTOOL=libtool
PLUGIN=pw-duo
LIBS=

all: $(PLUGIN).la

$(PLUGIN).lo: $(PLUGIN).c
	$(LIBTOOL) --mode=compile $(CC) $(CPPFLAGS) -c $?

$(PLUGIN).la: $(PLUGIN).lo
	$(LIBTOOL) --mode=link $(CC) -version-info 0:0:0 -rpath $(PREFIX)/lib -module -o $@ $? $(LIBS)
	#tar cvfzh ../pw-duo.tgz ../slapd-duo
	rm .libs/pw-duo.la
	cp pw-duo.la .libs


clean:
	rm -f $(PLUGIN).lo $(PLUGIN).la
	rm -f $(PLUGIN)
	mv $(PLUGIN).tgz /tmp/

install: $(PLUGIN).la
	mkdir -p $(PREFIX)/lib/
	$(LIBTOOL) --mode=install cp $(PLUGIN).la $(PREFIX)/lib/
	$(LIBTOOL) --finish $(PREFIX)/lib/

# install to my test VMs
test_install:
	sudo rsync -av .libs/ root@ldap1.test:/usr/lib/ldap/
	sudo rsync -av .libs/ root@ldap2.test:/usr/lib/ldap/
	sudo rsync -av /etc/duo root@ldap1.test:/etc/
	sudo rsync -av /etc/duo root@ldap2.test:/etc/
	sudo rsync -av /usr/local/duo root@ldap1.test:/usr/local/
	sudo rsync -av /usr/local/duo root@ldap2.test:/usr/local/
	sudo rsync -av add-pw-duo.sh root@ldap1.test:/tmp/
	sudo rsync -av add-pw-duo.sh root@ldap2.test:/tmp/
	echo  -e '\e[1;33;40mssh to test and run /tmp/pw-modify.sh\e[0;0m'

