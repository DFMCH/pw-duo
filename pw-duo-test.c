/*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted only as authorized by the OpenLDAP
* Public License.
*
* A copy of this license is available in the file LICENSE in the
* top-level directory of the distribution or, alternatively, at
* <http://www.OpenLDAP.org/license.html>.
*/
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>
#include "duo.h"
#include "pw-duo.h"

#define LUTIL_PASSWD_ERR -1
#define LUTIL_PASSWD_OK   0

/* read ikey, skey and host keys from DUO_LOGIN_CFG modifying passed struct members */
static int read_duo_keys (DuoConf *dc)
{
   int nread = 0;
   FILE *fin;
   char *ptr, *eos, *nl;
   char buf[255];
   int len = 0;
   fprintf(stderr, "%s: reading duo keys from %s\n", TAG, DUO_LOGIN_CFG);

   if ((fin = fopen (DUO_LOGIN_CFG, "r")) == NULL)
   {
      return -1;
   }

   while (!feof(fin))
   {
      if (fgets (buf, sizeof(buf), fin))
      {
         // if newline exists, replace with NULL 
         nl = strstr (buf, "\n");
         if (nl) { *(nl) = 0x0; }

         // if '=' found, trim out the key value and allocate/save keys values
         ptr = strstr (buf, "=");
         if (ptr)
         {
            while (*(++ptr) == ' ');
            eos = ptr;
            while ( (*(eos++) != ' ') && (*(eos++) != 0x0) );

            int len = eos - ptr;

            if (strstr (buf, DUO_CFG_IKEY))
            {
               if ( (dc->ikey = malloc (len + 1)) == NULL)
                  return -1;
               snprintf (dc->ikey, len, "%s", ptr);
            }
            else if (strstr (buf, DUO_CFG_API_HOST))
            {
               if ( (dc->api_host = malloc (len + 1)) == NULL)
                  return -1;
               snprintf (dc->api_host, len, "%s", ptr);
            }
            else if (strstr (buf, DUO_CFG_SKEY))
            {
               if ( (dc->skey = malloc (len + 1)) == NULL)
                  return -1;
               snprintf (dc->skey, len, "%s", ptr);
            }
         }
      }
   }

return nread;
}

int duo_auth_user (char *duo_username, int my_auth_mode, DuoConf *dc)
{
   int i = 0, auth_result = LUTIL_PASSWD_ERR;
   duo_t *duo;
   struct duo_auth *auth;
   struct duo_factor *dfact;
   char *api_host, *ikey, *skey, *factor;

   fprintf(stderr, "%s: DUO push auth for user %s\n", TAG, duo_username);

   if ( dc->api_host == NULL || dc->ikey == NULL || dc->skey == NULL )
   {
      fprintf(stderr, "%s: DUO keys not found in environment\n", TAG);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: env OK \n", TAG);

   if ( (duo = duo_init (dc->api_host, dc->ikey, dc->skey, "duo-check", NULL, NULL)) == NULL)
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

   /* could be any one of 'allow', 'deny', 'enroll' or 'auth'. Only process 'auth' for now  */
   if (strcmp (auth->ok.preauth.result, "auth") != 0)
   {
      fprintf(stderr, "%s: DUO did not return an auth condition (%s). Exiting.\n", TAG, auth->ok.preauth.result);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: result of preauth is auth \n", TAG);

   /* use a push */
   factor = NULL;

   while (factor == NULL)
   {
      for (i = 0; i < auth->ok.preauth.prompt.factors_cnt; i++)
      {
         dfact = &auth->ok.preauth.prompt.factors[i];
         fprintf(stderr, "%s: duo_fact prompt option %s has %s label\n", TAG, dfact->option, dfact->label);
      }

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
          /* TODO: add other auth methods here? */
         else
         {
            fprintf(stderr, "%s: using default option\n", TAG);
            factor = strdup(dfact->label);
            break;
         }
      }
   }


   auth = duo_auth_free(auth);
   fprintf(stderr, "%s: calling push\n", TAG);

   /*  not sure what the other options are for 3rd arg here. Going with what's in libduo/test-duologin.c See https://github.com/duosecurity/libduo/blob/master/duo.c  */
   if ( (auth = duo_auth_auth (duo, duo_username, "prompt", "1.2.3.4", (void *) factor)) == NULL)
   {
      fprintf(stderr, "%s: DUO push failed with error %s.\n", TAG, duo_get_error(duo));
      free (factor);
      return (LUTIL_PASSWD_ERR);
   }

   fprintf(stderr, "%s: push completed. Testing success.\n", TAG);

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

int main(int argc, char *argv[])
{
   DuoConf *dc;
   int num_cfg_keys = 0;

   dc = malloc (sizeof (DuoConf));
   if (!dc)
      return 0;

   if ( (num_cfg_keys = read_duo_keys (dc)) !=  DUO_CFG_TOTAL_KEYS)
   {
      fprintf(stderr, "%s: error encountered reading config keys (%d)\n", TAG, num_cfg_keys);
   }

   fprintf(stderr, "%s: read config result %d\n", TAG, num_cfg_keys);

   if (argc == 2)
   {
      duo_auth_user(argv[1], AUTH_MODE_PUSH, dc);
   }
   else
      fprintf(stderr, "%s: need a username to DUO auth.\n", TAG);

   printf ("host key is %s\n", dc->api_host);
   printf ("ikey is %s\n", dc->ikey);
   printf ("skey is %s\n", dc->skey);

   if (dc->ikey)
      free (dc->ikey);
   if (dc->skey)
      free (dc->skey);
   if (dc->api_host)
      free (dc->api_host);
   if (dc)
      free (dc);
}

