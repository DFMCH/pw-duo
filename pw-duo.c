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
#include "slap.h"      /* for struct SlapReply */
#include "lutil_sha1.h"
#include "duo.h"

#include <sasl/sasl.h>
#include <sasl/saslplug.h>

int slap_sasl_bind( Operation *op, SlapReply *rs );

static LUTIL_PASSWD_CHK_FUNC chk_duo_sasl;
static LUTIL_PASSWD_CHK_FUNC chk_duo_ssha1;

/* we use SASL passthrough for our passwords */
static const struct berval scheme_duo_sasl = BER_BVC("{DUO+SASL}");
/* ..and some SSHA as well */
static const struct berval scheme_duo_ssha1 = BER_BVC("{DUO+SSHA}");

static ldap_pvt_thread_mutex_t duo_sasl_mutex;

/* holds duo config/keys */
struct DUO_CONF {
   char *ikey;
   char *skey;
   char *host;
};

/*
 * macros for use with duo_auth
 */
/* available authentication options, returned from duo, start with this text and end with a 1 (for now I guess) */
#define LABEL_PREFIX_PUSH     "push"
#define LABEL_PREFIX_SMS      "sms"
#define LABEL_PREFIX_PHONE    "phone"

#define MODULE_NAME           "pw-duo"
#define TAG                   "chk_duo()"
#define DUO_LOGIN_CFG         "/etc/duo/login_duo.conf"  /* use login_duo for DUO keys */
#define DUO_TIMEOUT           20

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


/* from openldap-2.4.42+dfsg/servers/slapd/sasl.c */
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

//static sasl_security_properties_t sasl_secprops;
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

/* check Duo for an auth. return LUTIL_PASSWD_ERR or LUTIL_PASSWD_OK */
static int duo_auth_user (char *duo_username, int my_auth_mode)
{
   int i = 0, auth_result = LUTIL_PASSWD_ERR;
   duo_t *duo;
   struct duo_auth *auth;
   struct duo_factor *dfact;
   char *api_host, *ikey, *skey, *factor;

   fprintf(stderr, "%s: DUO push auth for user %s\n", TAG, duo_username);

   if ( (api_host = getenv("DUO_API_HOST")) == NULL ||
        (ikey = getenv("DUO_IKEY")) == NULL ||
        (skey = getenv("DUO_SKEY")) == NULL )
   {
      fprintf(stderr, "%s: DUO keys not found in environment\n", TAG);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: env OK \n", TAG);

   if ( (duo = duo_init (api_host, ikey, skey, "duo-check", NULL, NULL)) == NULL)
   {
      fprintf(stderr, "%s: DUO init failed\n", TAG);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: keys OK \n", TAG);

   if (duo_set_timeout (duo, DUO_TIMEOUT) != DUO_OK)
   {
      fprintf(stderr, "%s: DUO set timeout failed\n", TAG);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: timeout OK \n", TAG);

   /* preauth */
   if ( (auth = duo_auth_preauth (duo, duo_username)) == NULL)
   {
      fprintf(stderr, "%s: DUO preauth failed\n", TAG);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: preauth OK \n", TAG);

   /* could be any one of 'allow', 'deny', 'enroll' or 'auth'. Only process 'auth' for now */
   if (strcmp (auth->ok.preauth.result, "auth") != 0)
   {
      fprintf(stderr, "%s: DUO did not return an auth condition (%s). Exiting.\n", TAG, auth->ok.preauth.result);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: result of preauth is auth \n", TAG);

   /* ...push by default according to prompt text*/
   factor = NULL;

   // fprintf(stderr, "%s: prompt text is %s\n", TAG, auth->ok.preauth.prompt.text);

   while (factor == NULL)
   {
      for (i = 0; i < auth->ok.preauth.prompt.factors_cnt; i++)
      {
         dfact = &auth->ok.preauth.prompt.factors[i];
         fprintf(stderr, "%s: duo_fact prompt option %s has %s label\n", TAG, dfact->option, dfact->label);
      }

      /* find the push label and set factor to it.
       * current options could presumably change.
       * currently they are:
       * 1 push1
       * 2 phone1
       * 3 sms1
       */
      for (i = 0; i < auth->ok.preauth.prompt.factors_cnt; i++)
      {
         dfact = &auth->ok.preauth.prompt.factors[i];

         /* look for the prefix "push" in the duo label to send correct text option to auth server */
         if ( (my_auth_mode == AUTH_MODE_PUSH) && (strstr(LABEL_PREFIX_PUSH, dfact->label) == 0) )
         {
            fprintf(stderr, "%s: using option %s\n", TAG, LABEL_PREFIX_PUSH);
            factor = strdup(dfact->label);
            break;
         }
         /*
          * TODO: add other auth method checks here?
          */
         else
         {
            fprintf(stderr, "%s: using default option\n", TAG);
            factor = strdup(dfact->label);
            break;
         }
      }
   }

   auth = duo_auth_free(auth);
   fprintf(stderr, "%s: calling push for user %s\n", TAG, duo_username);

   /* not sure what the other options are for 3rd arg here. Going with what's in libduo/test-duologin.c See https://github.com/duosecurity/libduo/blob/master/duo.c */
   if ( (auth = duo_auth_auth (duo, duo_username, "prompt", "1.2.3.4", (void *) factor)) == NULL)
   {
      fprintf(stderr, "%s: DUO push failed with error %s.\n", TAG, duo_get_error(duo));
      free (factor);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: push completed. Testing result.\n", TAG);

   /* if Duo auth succeeded ... */
   if (strcmp(auth->ok.auth.result, "allow") == 0)
   {
      fprintf(stderr, "%s: DUO auth success %s.\n", TAG, auth->ok.auth.status_msg);
      auth_result = LUTIL_PASSWD_OK;
   }
   else
      fprintf(stderr, "%s: Auth failed\n", TAG);

   free (factor);
   auth = duo_auth_free(auth);
   duo_close(duo);

   return (auth_result);
}


/* check Duo push and SSHA password */
static int chk_duo_ssha1 (const struct berval *sc, const struct berval *passwd, const struct berval *cred,	const char **text )
{
	unsigned int i;

	int hash_auth_result = LUTIL_PASSWD_ERR; /* default to password error */
   int auth_result      = LUTIL_PASSWD_ERR;
   char *p_hash = NULL;                     /* points to actual password hash after username@ */
   char *duo_username = NULL;               /* points to duo user name from password hash */
   int len_user;

	for ( i = 0; i < cred->bv_len; i++ )
   {
		if ( cred->bv_val[ i ] == '\0' )
      {
         fprintf(stderr, "%s: NUL character in cred\n", TAG);
			return LUTIL_PASSWD_ERR;	/* NUL character in cred */
		}
	}

   if ( cred->bv_val[ i ] != '\0' )
   {
      fprintf(stderr, "%s: no NUL found at end\n", TAG);
		return LUTIL_PASSWD_ERR;	/* cred must behave like a string */
	}

	for ( i = 0; i < passwd->bv_len; i++ )
   {
		if ( passwd->bv_val[ i ] == '\0' )
      {
         fprintf(stderr, "%s: NUL char found in passwd\n", TAG);
			return LUTIL_PASSWD_ERR;	/* NUL character in password */
		}
	}

	if ( passwd->bv_val[ i ] != '\0' )
   {
      fprintf(stderr, "%s: no NUL found at end of passwd\n", TAG);
		return LUTIL_PASSWD_ERR;	/* passwd must behave like a string */
	}

   fprintf(stderr, "%s: looking for token in pass hash\n", TAG);
   /* DUO+SSHA userPassword must be provisioned as: {DUO+SSHA}username@ssha_hash
    * tried getting sAMAccountName using attr_find() but just can't find enough
    * info about how the function call works to make it work. For now, the username
    * must prefix the ssha_hash similar to the way the RADIUS and SASL plugins work
    *
    * Duo allows for users to be provisioned as user@somewhere.org which may result in
    * multiple '@' characters in userPassword so use strrchr() to find last occurrence
    */

   char *p_sep = strrchr(passwd->bv_val, PASS_HASH_SEPARATOR);
   if (!p_sep)
   {
      fprintf(stderr, "%s: separator not found or not valid DUO+SSHA password hash\n", TAG);
      return LUTIL_PASSWD_ERR;
   }

   /* next character after sep is pass hash */
   p_hash = p_sep + 1;

   /* username length is current p_sep pointer - beginning of passwd */
   len_user = p_sep - passwd->bv_val;

   /* check ssha password */
   lutil_SHA1_CTX SHA1context;
   unsigned char SHA1digest[LUTIL_SHA1_BYTES];
   unsigned char *orig_pass = NULL;
   size_t decode_len = LUTIL_BASE64_DECODE_LEN(strlen(p_hash));
   int rc;

   /* salt exists? */
   if (decode_len <= sizeof(SHA1digest))
   {
      return LUTIL_PASSWD_ERR;
   }

   orig_pass = (unsigned char *) ber_memalloc(decode_len + 1);
   if( orig_pass == NULL )
   {
      return LUTIL_PASSWD_ERR;
   }

   rc = lutil_b64_pton(p_hash , orig_pass, decode_len);

   /* safety check - must have a salt */
   if (rc <= (int)(sizeof(SHA1digest)))
   {
      ber_memfree(orig_pass);
      return LUTIL_PASSWD_ERR;
   }

   /* hash with salt */
   lutil_SHA1Init(&SHA1context);
   lutil_SHA1Update(&SHA1context, (const unsigned char *) cred->bv_val, cred->bv_len);
   lutil_SHA1Update(&SHA1context, (const unsigned char *) &orig_pass[sizeof(SHA1digest)], rc - sizeof(SHA1digest));
   lutil_SHA1Final(SHA1digest, &SHA1context);

   /* compare pass with digest */
   hash_auth_result = memcmp((char *)orig_pass, (char *)SHA1digest, sizeof(SHA1digest));
   ber_memfree(orig_pass);
   fprintf(stderr, "%s: ssha1_auth_result %d\n", TAG, hash_auth_result);

   // only perform duo auth if result is LUTIL_PASSWD_OK
   // TODO: The missing delay for an incorrect password guess may help an attacker enumerate valid passwords however
   if (hash_auth_result == LUTIL_PASSWD_OK)
   {
      duo_username = ber_memalloc (len_user + 1);

      if (!duo_username)
         return LUTIL_PASSWD_ERR;

      AC_MEMCPY(duo_username, passwd->bv_val, len_user);

      fprintf(stderr, "%s: running duo_auth_user() for user %s\n", TAG, duo_username);

      /* if auth_result is good, set auth_result for LUTIL_PASSWD_OK */
      auth_result = duo_auth_user (duo_username, AUTH_MODE_PUSH);

      fprintf(stderr, "%s: result is %d\n", TAG, auth_result);
      ber_memfree (duo_username);
   }
   else
   {
      fprintf(stderr, "%s: hash_auth_result returned an error. Skipping duo auth\n", TAG);
   }

	return auth_result;
}



/* check Duo push + SASL passthrough */
static int chk_duo_sasl (const struct berval *sc, const struct berval *passwd, const struct berval *cred,	const char **text )
{
	unsigned int i;
	int sasl_auth_result = LUTIL_PASSWD_ERR; /* default to password error */
   int auth_result      = LUTIL_PASSWD_ERR;
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

   /* check sasl password first */
   ctx = ldap_pvt_thread_pool_context();
   ldap_pvt_thread_pool_getkey( ctx, (void *)slap_sasl_bind, &sconn, NULL );

   if( sconn != NULL )
   {
      int sc;
      sc = sasl_checkpass( sconn, passwd->bv_val, passwd->bv_len, cred->bv_val, cred->bv_len );
      sasl_auth_result = ( sc != SASL_OK ) ? LUTIL_PASSWD_ERR : LUTIL_PASSWD_OK;
   }

   fprintf(stderr, "%s: sasl_auth_result %d\n", TAG, sasl_auth_result);

   /* only perform duo auth if sasl_auth_result is LUTIL_PASSWD_OK. */
   if (sasl_auth_result == LUTIL_PASSWD_OK)
   {
      /* for SASL auth, passwd->bv_val contains 'username@realm'. Duo accepts username@whatever so should we just send as is ? */
      fprintf(stderr, "%s: running duo_auth_user() for user %s\n", TAG, passwd->bv_val);

      /* if auth_result is good, set auth_result for LUTIL_PASSWD_OK */
      auth_result = duo_auth_user (passwd->bv_val, AUTH_MODE_PUSH);

      fprintf(stderr, "%s: result is %d\n", TAG, auth_result);
   }
   else
   {
      fprintf(stderr, "%s: SASL auth result returned and error. Skipping duo auth\n", TAG);
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
   int rc;

   fprintf(stderr, "%s: init_module - %s\n", TAG, MODULE_NAME);

   //DUO_CONF *duo_conf;
   //duo_conf = read_duo_keys(DUO_CFG);

   // might not need this? radius pw module uses it
	ldap_pvt_thread_mutex_init( &duo_sasl_mutex );

   rc = lutil_passwd_add( (struct berval *)&scheme_duo_ssha1, chk_duo_ssha1, NULL );
   if ( !rc )
	   rc = lutil_passwd_add( (struct berval *)&scheme_duo_sasl, chk_duo_sasl, NULL );

   return (rc);
}
