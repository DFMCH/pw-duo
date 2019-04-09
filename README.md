# pw-duo
pw-duo is an OpenLDAP password module implementing Duo Push with SASL passthrough authentication and/or SSHA password hashes

# Overview
The module needs a configured OpenLDAP source branch to be built against. Once built, the module is copied to the OpenLDAP server (eg: under `/usr/lib/ldap`) and added to the slapd instance with an LDIF file. Once in place, a user's `userPassword` attribute is configured with a special "prefix" to tell `slapd` to run the pw-duo module for authentication instead of the built-in OpenLDAP methods. The pw-duo module will first attempt authentiation (depending on configuration) via SASL passthrough, or by comparing SSHA password hashes. If the previous auth method is succesful, the Duo push is attempted. If either method fails, authentication fails. By initiating the Duo push at the LDAP layer, any application requesting authentication via LDAP will initiate a Duo push without the need to modify any application source code.

This is an early work in progress. My experience with C is limited to projects much smaller than the OpenLDAP code base. That said, there are things that could be improved on. For instance, it would make much more sense to call the 1FA functions already defined in OpenLDAP core and only handle the Duo 2FA from the module. When I tried this however, it created some warnings about redefined macros. It's most likely that I included the wrong header file. It wasn't obvious where the issue was so finally I opted to include the SASL and SSHA auth bits I needed directly into the pw-duo module itself. This resulted in a cleaner build and a good time to mention OpenLDAP is a registered trademark of the OpenLDAP Foundation and [where to find the OpenLDAP License](http://www.openldap.org/software/release/license.html)

A few problems I wanted to address with pw-duo:

- incorporate Duo push at the LDAP layer so it is transparent to applications performing authentication
- fix for "BERDecoderContext has no tag..." issues when running Duo Authentication Proxy (authentication always fails)
- eliminate/minimize the amount of code needed to be touched to implement Duo

This module addresses the three points above however there are some caveats:

- the inherent delay incorporated into the authentication process may not work for all applications.  I've tested it so far with `sudo` and a handful of in-house web apps but not a great sample size so far
- some applications have a mixed user configuration - some in LDAP, some defined locally. An application level implementation would work best here
- `slapd` allows about 10 seconds to accept the Duo push before [`deferring operation`](http://www.openldap.org/lists/openldap-software/200704/msg00094.html) occurrs which terminates authentication. I don't know yet if this is adjustable.

The pw-duo module must be compiled against the source code headers of the version of slapd (OpenLDAP) you intend to be running the module on. There are a few headers which are generated during configure or compile time which need to be included in the module (portable.h is one).

The userPassword attribute (in your LDAP DIT) for any given user being configured for use with this module must be specified in one of these particular formats or the module will not be invoked for the user.

```
{DUO+SASL}userLogin@SASL_realm (Example: {DUO+SASL}user101@mydomain.com)
{DUO+SSHA}userLogin@SSHA_HASH  (Example: {DUO+SSHA}user101@2jmj7l5rSw0yVb/vlWAYkK/YBwk=)
```

DUO+SASL defines a user provisioned for SASL passthrough auth to another server, while DUO+SSHA would define a user authentication with an SSHA password hash included after the ampersand. The username/login is included in both schemes. Initially, I tried to retrieve this information during runtime but was unsuccesful. I wondered if maybe the other modules (radius, SASL) in the contrib directory included the login name for the same reason.  This does have the added benefit of allowing the Duo username to be different than the login username so that may have some benefits in mixed environments. TODO: Found out later that Duo allows for 'user@domain.net' so there may be multiple ampersands in the userPassword attribute. The module doesn't currently handle this but should be an easy fix (using strrchar() instead)

# Building
Steps:

* download configure and build the OpenLDAP source
* download configure and build libduo as a shared library
* download and build the pw-duo module

This module is compiled against Ubuntu 16.04, openldap-2.4.42+dfsg source package, and the [Duo libduo C library](https://github.com/duosecurity/libduo). Additionally, you will need to install the `libcrypto` and `libssl` development files also. The Ubuntu source package can be installed to the current directory like this:
```sh
# apt-get source slapd
```
The build configuration was setup by looking through the [xenial buildlog on launchpadlibrarian](https://launchpadlibrarian.net/321982631/buildlog_ubuntu-xenial-amd64.openldap_2.4.42+dfsg-2ubuntu3.2_BUILDING.txt.gz) (specifically the dh_auto_configure line)

Mine looks like this:

```
$ ./configure --build=x86_64-linux-gnu --prefix=/usr --includedir=${prefix}/include --mandir=${prefix}/share/man --infodir=${prefix}/share/info \
--sysconfdir=/etc --localstatedir=/var --disable-silent-rules --libdir=${prefix}/lib/x86_64-linux-gnu --libexecdir=${prefix}/lib/x86_64-linux-gnu \
--disable-maintainer-mode --disable-dependency-tracking --prefix=/usr/local/openldap-2.4.42-tmb --libexecdir=${prefix}/lib --sysconfdir=/etc \
--localstatedir=/var --mandir=${prefix}/share/man --enable-debug --enable-dynamic --enable-syslog --enable-proctitle --enable-ipv6 --enable-local \
--enable-slapd --enable-dynacl --enable-aci --enable-cleartext --enable-crypt --disable-lmpasswd --enable-spasswd --enable-modules --enable-rewrite \
--enable-rlookups --enable-slapi --enable-slp --enable-wrappers --enable-backends=mod --disable-ndb --enable-overlays=mod --with-subdir=ldap \
--with-cyrus-sasl --with-threads --with-gssapi --with-tls=gnutls --with-odbc=unixodbc --enable-memberof --enable-ppolicy --enable-accesslog \
--enable-dynamic --disable-slapd --enable-passwd
```

After configuring OpenLDAP, run `make depend` to build. This will not install the slapd build, but will create the neccesary header files which are needed to build pw-duo

Next, pull in the Duo libduo C library and configure/build the library:
```
$ git clone https://github.com/duosecurity/libduo.git
```

The OpenLDAP module seems to only work built with shared libraries (maybe due to `--enable-dynamic` above?). The libduo library is built statically. I opted to build libduo as a shared library. This requires editing the libduo Makefile and adding `-fPIC` to the `CFLAGS` make variable or simply exporting `CFLAGS` prior to running `./configure`.

Proceed with make and then build libduo.so from the `.o` files:

```
$ cd libduo
$ export CFLAGS="-fPIC"
$ ./configure
...

$ make
gcc -fPIC -Wall -D_FORTIFY_SOURCE=2 -fstack-protector -I. -I.   -DDUODIR=\"/usr/local/etc\" -DHAVE_CONFIG_H -c duo.c
...
/usr/bin/ar rv libduo.a duo.o http_parser.o https.o match.o parson.o urlenc.o
/usr/bin/ar: creating libduo.a
...

$ gcc -shared urlenc.o parson.o match.o https.o http_parser.o duo.o  -o libduo.so
```

You should now have a `libduo.so` under the libduo directory. Next, cd to `contrib/slapd-modules/passwd` and clone the pw-duo repo in.
Copy the pw-duo and pw-duo-test source code and Makefile into the passwd directory (overwites the Makefile included with OpenLDAP so may want to back it up):
```
$ git clone https://github.com/DFMCH/pw-duo.git
$ cp pw-duo/pw-duo.c .
$ cp pw-duo/pw-duo-test.c .
$ cp pw-duo/Makefile .
$ make

```
This should produce the pw-duo OpenLDAP password module in the `.libs` sub directory


# Installing
Steps:

* copy the pw-duo.so.x.x.x modules to the LDAP server
* add the pw-duo module to the LDAP server
* copy the libduo shared library to the LDAP server
* configure the dynamic linker (ld) for libduo
* install the Duo keys on the LDAP server
* export the Duo keys to the slapd environment
* restart the LDAP server in debug mode to test
* configure a user account for pw-duo

After building, tar or rsync the pw-duo `pw-duo.so*` files from the `.libs/` build directory into the correct OpenLDAP module directory on the LDAP server. On Ubuntu 16.04 this is `/usr/lib/ldap/`.

Copy the `libduo/libduo.so` shared library to some location on the LDAP server (I use `/usr/local/duo/lib/`) and configure the kernel for the new library.
You should see libduo.so.x.x.x in the `ldconfig` output:

```
$ echo "/usr/local/duo/lib" > /etc/ld.so.conf.d/libduo.conf
$ ldconfig -v
/usr/local/duo/lib:
        libduo.so.0.0.0 -> libduo.so.0.0.0
...
```

Your Duo keys are generated in your Duo admin portal and will need to be on the LDAP server. The simplest convention I found is to rsync `/etc/duo` from a system setup for something like `duo_unix` (using the `login_duo` application) to the LDAP server and then pull those into the environment.

TODO: Need to expose the DUO keys to the slapd environment somehow. This is what I currently use for testing (run as root):
```sh
# export DUO_API_HOST=$(sudo egrep ^host /etc/duo/login_duo.conf  | awk '{print $3};')
# export DUO_IKEY=$(sudo egrep ^ikey  /etc/duo/login_duo.conf  | awk '{print $3};')
# export DUO_SKEY=$(sudo egrep ^skey  /etc/duo/login_duo.conf  | awk '{print $3};')

# slapd -u openldap -d64 -h "ldap:/// ldaps:/// ldapi:///"
```

I'm not exactly sure how best to remove an openldap module after it has been added. The question has been [brought up](https://www.openldap.org/lists/openldap-technical/201308/msg00162.html). It's probably best to make a [slapcat backup](https://help.ubuntu.com/lts/serverguide/openldap-server.html.en) before adding the module. If you want to remove the module, restore from the slapcat dump.

Once your backup is in place, add the pw-duo module to slapd with the included shell script `add-pw-duo.sh` (or appropriate LDIF file).

After adding the module, you can see if it's loading by running slapcat again. STDERR will have a pw-duo message. As far as I know, this message has always been harmless and is a nice way of checking if the module is working (you can always comment it out and recompile).

```sh
  # slapcat > /tmp/foo
  chk_duo(): init_module - pw-duo
  chk_duo(): term_module - pw-duo
```

Lastly, in your LDAP DIT, find a user to test with and prefix the `userPassword` attribute as shown above. This will tell slapd to run the pw-duo password module for that user everytime authentication is performed. Authentication for that account will now use Duo push in addition to SASL or SSHA authentication.

Also, be sure to check permissions on all the files copied over. root should own them all with restricted permissions on `/etc/duo` especially.


