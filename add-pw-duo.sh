#!/bin/bash
# /*
# * Redistribution and use in source and binary forms, with or without
# * modification, are permitted only as authorized by the OpenLDAP
# * Public License.
# *
# * A copy of this license is available in the file LICENSE in the
# * top-level directory of the distribution or, alternatively, at
# * <http://www.OpenLDAP.org/license.html>.
# */
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

