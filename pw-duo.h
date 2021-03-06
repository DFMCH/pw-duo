/*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted only as authorized by the OpenLDAP
* Public License.
*
* A copy of this license is available in the file LICENSE in the
* top-level directory of the distribution or, alternatively, at
* <http://www.OpenLDAP.org/license.html>.
*/

#ifndef pw_duo_h
#define pw_duo_h

#define DUO_TIMEOUT        20

/* available authentication options, returned from duo, start with this text and end with a 1 (for now I guess) */
#define LABEL_PREFIX_PUSH     "push"
#define LABEL_PREFIX_SMS      "sms"
#define LABEL_PREFIX_PHONE    "phone"
#define DUO_AUTH_FACTOR       "prompt"
#define DUO_AUTH_IPADDR       "1.2.3.4"   /* if we can get the IP of the host requesting auth it would go here */

#define MODULE_NAME           "pw-duo"
#define TAG                   "chk_duo()"
#define DUO_LOGIN_CFG         "/etc/duo/login_duo.conf"  /* use login_duo for DUO keys */
#define DUO_TIMEOUT           20

/* key=value text from login_duo.conf config file */
#define DUO_CFG_IKEY          "ikey"
#define DUO_CFG_SKEY          "skey"
#define DUO_CFG_API_HOST      "host"
#define DUO_CFG_TOTAL_KEYS    3

/* just use AUTH_MODE_PUSH for now. maybe later this could be specified in the username/password input
 * TODO: could parse the option from username or password.
 * it's a non-interactive auth, so which mode to use?
 * eg: 302233,username or 302303,Pa55w0rd
 * eg: sms,username or sms,Pa55w0rd
 * eg: phone,username or phone,Pa55w0rd
 */
#define AUTH_MODE_PUSH     100
#define AUTH_MODE_SMS      101
#define AUTH_MODE_PHONE    102
#define AUTH_MODE_PCODE    103

#define PASS_HASH_SEPARATOR '@'  /* used in LDAP userPassword attribute for SSHA auth */


/* holds duo config/keys */
typedef struct duo_conf {
   char *ikey;
   char *skey;
   char *api_host;
} DuoConf;


#endif /* pw-duo.h */
