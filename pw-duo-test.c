#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>

#include "duo.h"

#define LUTIL_PASSWD_ERR   -1
#define LUTIL_PASSWD_OK    -1
#define DUO_TIMEOUT        20
#define TAG                "duo-test"

/* available authentication options, returned from duo, start with this text and end with a 1 (for now I guess) */
#define LABEL_PREFIX_PUSH        "push"
#define LABEL_PREFIX_SMS         "sms"
#define LABEL_PREFIX_PHONE       "phone"

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


int duo_auth_user (char *duo_username, int my_auth_mode)
{
   int auth_result = LUTIL_PASSWD_ERR;
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

   /* use a push */
   factor = NULL;

   // fprintf(stderr, "%s: prompt text is %s\n", TAG, auth->ok.preauth.prompt.text);

   int i = 0;
   char buf[128];

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
         if ( (my_auth_mode == AUTH_MODE_PUSH) && (strcasestr(LABEL_PREFIX_PUSH, dfact->label) == 0) )
         {
            fprintf(stderr, "%s: using option %s\n", TAG, LABEL_PREFIX_PUSH);
            factor = strdup(dfact->label);
            break;
         }
         /*
          * TODO: add other auth methods here?
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
   fprintf(stderr, "%s: calling push with buf %s\n", TAG, buf);

   /* not sure what the other options are for 3rd arg here. Going with what's in libduo/test-duologin.c See https://github.com/duosecurity/libduo/blob/master/duo.c */
   if ( (auth = duo_auth_auth (duo, duo_username, "prompt", "1.2.3.4", (void *) factor)) == NULL)
   {
      fprintf(stderr, "%s: DUO push failed with error %s.\n", TAG, duo_get_error(duo));
      free (factor);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: push completed. Testing success.\n", TAG);

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

int main(int argc, char *argv[])
{
   if (argc == 2)
   {
      duo_auth_user(argv[1], AUTH_MODE_PUSH);
   }
   else
      fprintf(stderr, "%s: need a username to DUO auth.\n", TAG);
}
