# $OpenLDAP$
#CPPFLAGS+=-Iopenldap-2.4.31/include -Ifreeradius-client-1.1.6/include/ -fPIC -Wall
# 2016-01-05 tmb -i can't compile radexample unless freeradius-1.1.6 source is included
# CPPFLAGS+=-Iopenldap-2.4.31/include -Ifreeradius-client-1.1.6/include/ -fPIC -Wall
# 2016-01-05 - tmb - with 14.04, we can use ubuntu libfreeradius-client-dev package and no need 
# to download source. Can't compile radexampel however because it needs config.h from source which
# not sure CPPFLAGS+=-Iopenldap-2.4.31/include -fPIC -Wall
# CPPFLAGS+=-Iopenldap-2.4.31/include -L/usr/src/freeradius-client/lib/ -I/usr/src/freeradius-client/include/ -shared -fPIC -dPIC -Wall
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

test_install:
	rsync -av .libs/ root@ldap1.test:/usr/lib/ldap/
	rsync -av .libs/ root@ldap2.test:/usr/lib/ldap/
	rsync -av /etc/duo root@ldap1.test:/etc/
	rsync -av /etc/duo root@ldap2.test:/etc/
	rsync -av /usr/local/duo root@ldap1.test:/usr/local/
	rsync -av /usr/local/duo root@ldap2.test:/usr/local/
	rsync -av pw-modify.sh root@ldap1.test:/tmp/
	rsync -av pw-modify.sh root@ldap2.test:/tmp/
	echo  -e '\e[1;33;40mssh to test and run /tmp/pw-modify.sh\e[0;0m'

