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
#include "pw-duo/pw-duo.h"

#define LUTIL_PASSWD_ERR -1
#define LUTIL_PASSWD_OK   0


static int read_duo_keys (DuoConf *dc)
{
   int nread = 0;
   FILE *fin;
   char *ptr;
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
         /* skip lines starting with semicolons */
         if (strstr (buf, ";"))
         {
            char *tmp = buf;
            while (*(++tmp) == ' ');
            if (*(tmp) == ';')
            {
               printf ("found comment with leading whitespace\n");
               continue;
            }
         }

         /* if newline exists, replace with NULL */
         char *nl = strstr (buf, "\n");
         if (nl)
            *(nl) = 0x0;

         char *ptr = strstr (buf, "=");
         if (ptr)
         {
            while (*(++ptr) == ' ');
            len = buf + strlen (buf) - ptr;

            if (strstr (buf, "ikey ") || strstr (buf, "ikey="))
            {
               printf (" ikey is |%s| len is %d\n", ptr, len);
               dc->ikey = malloc (len + 1);
               if (dc->ikey) snprintf (dc->ikey, len, "%s", ptr);
            }
            else if (strstr (buf, "host ") || strstr (buf, "host="))
            {
               printf (" host is |%s| len is %d\n", ptr, len);
               dc->host = malloc (len + 1);
               if (dc->host) snprintf (dc->host, len, "%s", ptr);
            }
            else if (strstr (buf, "skey ") || strstr (buf, "skey="))
            {
               printf (" skey is |%s| len is %d\n", ptr, len);
               dc->skey = malloc (len + 1);
               if (dc->skey) snprintf (dc->skey, len, "%s", ptr);
            }

         }/* if ptr */

      }/* fgets */
   }

return nread;
}

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
   DuoConf *dc;

   dc = malloc (sizeof (DuoConf));
   if (!dc)
      return 0;

   int cfg_result = read_duo_keys (dc);

   fprintf(stderr, "%s: read config result %d\n", TAG, cfg_result);

   if (argc == 2)
   {
      duo_auth_user(argv[1], AUTH_MODE_PUSH);
   }
   else
      fprintf(stderr, "%s: need a username to DUO auth.\n", TAG);

   printf ("host key is %s\n", dc->host);
   printf ("ikey is %s\n", dc->ikey);
   printf ("skey is %s\n", dc->skey);

   if (dc->ikey) free (dc->ikey);
   if (dc->skey) free (dc->skey);
   if (dc->host) free (dc->host);
   if (dc) free (dc);
}
