#!/bin/bash

test ! -d /usr/lib/ldap && { echo "No /usr/lib/ldap directory found. bye."; exit 1; }

echo "adding DUO ldap module to slapd config..."
rand=`mktemp`
cat > $rand <<EOF
dn: cn=module,cn=config
cn: module
objectclass: olcModuleList
objectclass: top
olcModuleLoad: pw-duo
olcmodulepath: /usr/lib/ldap
EOF

ldapadd -Y EXTERNAL -H ldapi:/// -f $rand

