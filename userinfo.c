/*
    Big Dumb Finger Daemon - a secure, highly configurable finger daemon
    Copyright (C) 2002  Lebbeous Weekley
  
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
  
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
  
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  
    The author maybe reached via lebbeous@gmail.com
*/

/* userinfo.c   for bdfingerd */

/*

 userinfo.c - contains the function that matches
  a given token to users on the system
  by parsing the passwd file: search_passwd_file

  search_passwd_file returns a struct
  userinfo_s *  which is a pointer to a linked
  list containing all matching entries

  once this function had been called and the
  linked list obtained, special files for that
  user can be referenced by that user's name
  (the 'name' member of the userinfo structure)
  in the 'special file directory' (usually
  /var/spool/finger) determined by bdfingerd's
  conf file.

*/

#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>

#include "bdfinger.h"

/* LW: 26/3 Changing the search_passwd_file() function to use the setpwent/getpwent
   system, and created a linked list of all entries. added the match_passwd_entry
   function below  */

struct userinfo_s *
search_passwd_file (void)
{

    int i, j, k;
    char *p, *gtok;
    char *gecos;
    struct passwd *pw;

    struct userinfo_s ui;       /* this one is for internal use */
    struct userinfo_s *walker = NULL;
    struct userinfo_s *ui_list = NULL;


    setpwent ();                /* returns no error */

    do
    {

        pw = getpwent ();
        if (!pw)
        {
            break;              /* no more entries */
        }

        memset (&ui, 0, sizeof (struct userinfo_s));

        strncpy (ui.name, pw->pw_name, 31);
        strncpy (ui.homedir, pw->pw_dir, 255);
        strncpy (ui.shell, pw->pw_shell, 63);
        ui.uid = pw->pw_uid;
        ui.gid = pw->pw_gid;

        gecos = malloc (strlen (pw->pw_gecos) + 1);
        if (gecos)
        {
            memset (gecos, 0, strlen (pw->pw_gecos) + 1);
            strcpy (gecos, pw->pw_gecos);
        }
        else
        {
            perror ("malloc");
            return NULL;
        }


        j = 0;                  /* gecos index */
        k = 0;                  /* ui.whatever index */

        /* FIXME: this will later affect the way in which tokens
           * are compared to users' real names, such that anybody with
           * a really long real name may not match up properly, since
           * the comparison with the query token will only be done
           * with the truncated version of the realname (to 31 chars).
         */
        do
        {

            if (gecos[j] != ',')        /* we're in realname range */
            {
                while (gecos[j] != ',' && gecos[j] != '\0')
                {
                    if (k < 31)
                    {
                        if (gecos[j] == '&')
                        {
                            strncat (ui.realname, ui.name, 31 - k);
                            ui.realname[k] = toupper (ui.realname[k]);
                            k += strlen (ui.name);
                        }
                        else
                            ui.realname[k++] = gecos[j];
                    }
                    j++;
                }
            }
            if (gecos[j] == ',')        /* we're in office range */
            {
                k = 0;
                j++;
                while (gecos[j] != ',' && gecos[j] != '\0')
                {
                    if (k < 31)
                        ui.office[k++] = gecos[j];
                    j++;
                }
            }
            else
                break;
            if (gecos[j] == ',')        /* we're in office no. range */
            {
                k = 0;
                j++;
                while (gecos[j] != ',' && gecos[j] != '\0')
                {
                    if (k < 31)
                        ui.officephone[k++] = gecos[j];
                    j++;
                }
            }
            else
                break;
            if (gecos[j] == ',')        /* we're in home phone range */
            {
                k = 0;
                j++;
                while (gecos[j] != ',' && gecos[j] != '\0')
                {
                    if (k < 31)
                        ui.homephone[k++] = gecos[j];
                    j++;
                }
            }
            else
                break;
            break;
        }
        while (1);

        free (gecos);

        if (!ui_list)
        {
            walker = ui_list = malloc (sizeof (struct userinfo_s));
            if (!ui_list)
            {
                perror ("malloc");
                return NULL;
            }
            memcpy (ui_list, &ui, sizeof (struct userinfo_s));
            ui_list->next = NULL;
        }
        else
        {
            if (!walker)
            {
                return ui_list; /* a problem exists here */
            }
            walker->next = malloc (sizeof (struct userinfo_s));
            if (!walker->next)
                return ui_list; /* out of memory */
            memcpy (walker->next, &ui, sizeof (struct userinfo_s));
            walker->next->next = NULL;
            walker = walker->next;
        }


    }
    while (pw);


    endpwent ();

    return ui_list;
}


/* match_passwd_entry returns a linked list to all entries
   in 'userinfo' that have a matching username or login
   name to the supplied variable 'name' */

struct userinfo_s *
match_passwd_entry (char *name)
{
    struct userinfo_s *u;
    struct userinfo_s *list = NULL, *walker = NULL;
    int match;
    char *tok, *s2;


    u = userinfo;


    while (u)
    {

        match = 0;

        /* this section checks the supplied token against all space-separated
           segments of the realname */
        if (matchrealnames->value)
        {
            s2 = strdup (u->realname);

            if (!s2)
                perror ("strdup");
            else
            {
                for (tok = strtok (s2, " \t\r\n"); tok;
                     tok = strtok (NULL, " \t\r\n"))
                {
                    if (strcasecmp (tok, name) == 0)
                        match = 1;
                }
                free (s2);
            }
        }

        if (((strcasecmp (u->name, name) == 0) ||
             ((strcasecmp (u->realname, name) == 0) && matchrealnames->value)
             || (match)) && (showroot->value || u->uid != 0)
            && (ignorenofinger->value || (!check_nofinger (u))))
        {


            if (!list)
            {
                walker = list = malloc (sizeof (struct userinfo_s));
                if (!walker)
                {
                    perror ("malloc");
                    return NULL;
                }
                else
                {
                    memcpy (walker, u, sizeof (struct userinfo_s));
                    walker->next = NULL;        /* ESSENTIAL! */
                }
            }

            else
            {
                walker = list;
                while (walker->next)
                    walker = walker->next;

                walker->next = malloc (sizeof (struct userinfo_s));
                if (!walker->next)
                {
                    perror ("malloc");
                    return list;
                }
                else
                {
                    memcpy (walker->next, u, sizeof (struct userinfo_s));
                    walker->next->next = NULL;  /* ESSENTIAL! */
                }

            }
        }

        u = u->next;
    }

    return list;
}
