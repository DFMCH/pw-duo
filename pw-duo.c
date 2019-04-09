#include "portable.h" /* need to ./configure openldap source to get this file (symlink in current directory) */
#include <stdio.h>
#include <lber.h>
#include <lber_pvt.h>   /* BER_BVC definition */
#include "lutil.h"  /* need to ./configure openldap source to get this file (symlink in current directory) */
#include <ldap_pvt_thread.h>
#include <ac/string.h> /* need to ./configure openldap source to get this file (symlink in current directory) */
#include <ac/unistd.h> /* need to ./configure openldap source to get this file (symlink in current directory) */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../openldap-2.4.42+dfsg/servers/slapd/sasl.c"
int slap_sasl_bind( Operation *op, SlapReply *rs );

#define MODULE_NAME     "pw-duo"
#define TAG             "chk_duo()"
#define LOGIN_DUO       "/usr/local/duo/sbin/login_duo"
#define LOGIN_DUO_FLAGS " -n -f "

static LUTIL_PASSWD_CHK_FUNC chk_duo_sasl;
static const struct berval scheme = BER_BVC("{DUO+SASL}");
static ldap_pvt_thread_mutex_t duo_sasl_mutex;

// login_duo shell exit codes
#define DUO_AUTH_SUCCESS 0
#define DUO_AUTH_FAIL    1

// from openldap-2.4.42+dfsg/servers/slapd/sasl.c
#ifdef HAVE_CYRUS_SASL
# ifdef HAVE_SASL_SASL_H
#  include <sasl/sasl.h>
#  include <sasl/saslplug.h>
# else
#  include <sasl.h>
#  include <saslplug.h>
# endif

# define SASL_CONST const

#define SASL_VERSION_FULL  ((SASL_VERSION_MAJOR << 16) |\
   (SASL_VERSION_MINOR << 8) | SASL_VERSION_STEP)

#if SASL_VERSION_MINOR >= 0x020119 /* 2.1.25 */
typedef sasl_callback_ft slap_sasl_cb_ft;
#else
typedef int (*slap_sasl_cb_ft)();
#endif

static sasl_security_properties_t sasl_secprops;
#elif defined( SLAP_BUILTIN_SASL )
/*
 * built-in SASL implementation
 * only supports EXTERNAL
 */
typedef struct sasl_ctx {
   slap_ssf_t sc_external_ssf;
   struct berval sc_external_id;
} SASL_CTX;

#endif

static int chk_duo_sasl (const struct berval *sc, const struct berval *passwd, const struct berval *cred,	const char **text )
{
	unsigned int i;

	int sasl_auth_result = LUTIL_PASSWD_ERR; /* default to password error */
   int auth_result      = LUTIL_PASSWD_ERR;
   int duo_auth_result  = DUO_AUTH_FAIL;    // default to fail
   char duo_cmd[512];                       // holds system() call to login_duo
   void *ctx, *sconn = NULL;                // for sasl


   fprintf(stderr, "%s: starting chk_duo_sasl\n", TAG);

	for ( i = 0; i < cred->bv_len; i++ )
   {
		if ( cred->bv_val[ i ] == '\0' )
      {
			return LUTIL_PASSWD_ERR;	/* NUL character in cred */
		}
	}

   if ( cred->bv_val[ i ] != '\0' )
   {
		return LUTIL_PASSWD_ERR;	/* cred must behave like a string */
	}

	for ( i = 0; i < passwd->bv_len; i++ )
   {
		if ( passwd->bv_val[ i ] == '\0' )
      {
			return LUTIL_PASSWD_ERR;	/* NUL character in password */
		}
	}

	if ( passwd->bv_val[ i ] != '\0' )
   {
		return LUTIL_PASSWD_ERR;	/* passwd must behave like a string */
	}

   fprintf(stderr, "%s: checking user %s\n", TAG, passwd->bv_val);

	ldap_pvt_thread_mutex_lock( &duo_sasl_mutex );

   // check sasl password
   ctx = ldap_pvt_thread_pool_context();
   ldap_pvt_thread_pool_getkey( ctx, (void *)slap_sasl_bind, &sconn, NULL );

   if( sconn != NULL )
   {
      int sc;
      sc = sasl_checkpass( sconn, passwd->bv_val, passwd->bv_len, cred->bv_val, cred->bv_len );
      sasl_auth_result = ( sc != SASL_OK ) ? LUTIL_PASSWD_ERR : LUTIL_PASSWD_OK;
   }

   fprintf(stderr, "%s: sasl_auth_result %d\n", TAG, sasl_auth_result);

   // only perform duo auth if sasl_auth_result is LUTIL_PASSWD_OK.
   // strip username for bunk or garbage, don't send to shell. A downside of system() call
   if (sasl_auth_result == LUTIL_PASSWD_OK)
   {
      memset (duo_cmd, 0x0, sizeof(duo_cmd));
      int total_len = strlen (passwd->bv_val) + strlen (LOGIN_DUO) + strlen (LOGIN_DUO_FLAGS);
      if (total_len < sizeof(duo_cmd))
      {
         snprintf (duo_cmd, sizeof(duo_cmd), "%s%s%s", LOGIN_DUO, LOGIN_DUO_FLAGS, passwd->bv_val);
         fprintf(stderr, "%s: running duo_cmd %s for user %s\n", TAG, duo_cmd, passwd->bv_val);
         duo_auth_result = system (duo_cmd);
         fprintf(stderr, "%s: login_duo result for %s was %d\n", TAG, passwd->bv_val, duo_auth_result);

         // if duo_auth_result is good, set auth_result for LUTIL_PASSWD_OK
         if (duo_auth_result == DUO_AUTH_SUCCESS)
            auth_result = ( duo_auth_result != DUO_AUTH_SUCCESS ) ? LUTIL_PASSWD_ERR : LUTIL_PASSWD_OK;
      }
      else
         fprintf(stderr, "%s: total_len is too big for command buffer. Skipping duo auth\n", TAG);
   }

	ldap_pvt_thread_mutex_unlock( &duo_sasl_mutex );


	return auth_result;
}


int term_module()
{
   fprintf(stderr, "%s: term_module - %s\n", TAG, MODULE_NAME);
	return ldap_pvt_thread_mutex_destroy( &duo_sasl_mutex );
}

int init_module( int argc, char *argv[] )
{
   fprintf(stderr, "%s: init_module - %s\n", TAG, MODULE_NAME);
	ldap_pvt_thread_mutex_init( &duo_sasl_mutex );
	return lutil_passwd_add( (struct berval *)&scheme, chk_duo_sasl, NULL );
}
