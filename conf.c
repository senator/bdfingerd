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

/* conf.c  for bdfinger */

/* this file containes the parse_conf_file function, which does
  pretty much what it sounds like it would do. command line
  options must be handled in such a way that they take precedence
  over conf file settings.  the obvious exception would be an
  option to specify where to load a conf file from - perhaps like

    bdfingerd -c /opt/etc/bdfingerd.conf

  which would have to be handled early on.

  The conf file should support comments prepended with #'s, the
  ignoring of whitespace-only lines, lines to set variables like:
     SPECIAL_FILES_DIR=/var/spool/finger
  and lines to activate boolean variables like
     UPTIME

*/

#include <stdio.h>
#include <string.h>

#include "bdfinger.h"



cvar_t *cvar_head = (cvar_t *) NULL;


int
init_cvars (void)
{
    int rvalue = 0;


    /* begin new_cvar() */

    cvar_t *new_cvar (char *name, char *string)
    {
        cvar_t *p, *r;

        if (!cvar_head)
        {
            cvar_head = (cvar_t *) malloc (sizeof (cvar_t));
            p = cvar_head;
        }
        else
        {
            for (r = cvar_head; r->next; r = r->next);

            r->next = (cvar_t *) malloc (sizeof (cvar_t));
            p = r->next;
        }

        if (!p)
        {
            rvalue = -1;
            return (cvar_t *) NULL;
        }

        memset (p->name, 0, sizeof (p->name));
        memset (p->string, 0, sizeof (p->string));

        strncpy (p->name, name, CVAR_NAME_MAX - 1);
        strncpy (p->string, string, CVAR_STRING_MAX - 1);
        p->value = atoi (p->string);

        p->next = (cvar_t *) NULL;

        return p;
    }
    /* end new_cvar() */

    if (cvar_head)
        destroy_cvars ();

    repository = new_cvar ("REPOSITORY", "/var/spool/finger");
    pidfile = new_cvar ("PIDFILE", "/tmp/bdfingerd.pid");
    maxchildren = new_cvar ("MAXCHILDREN", "30");
    timeout = new_cvar ("TIMEOUT", "30");
    port = new_cvar ("PORT", "79");
    safeuser = new_cvar ("SAFEUSER", "nobody");
    tty = new_cvar ("TTY", "0");
    welcome = new_cvar ("WELCOME", "0");
    uptime = new_cvar ("UPTIME", "0");
    allowempty = new_cvar ("ALLOWEMPTY", "0");
    multistyle = new_cvar ("MULTISTYLE", "SHORT");
    logging = new_cvar ("LOGGING", "0");
    showroot = new_cvar ("SHOWROOT", "0");
    eurodates = new_cvar ("EURODATES", "0");
    forwarding = new_cvar ("FORWARDING", "0");
    matchrealnames = new_cvar ("MATCHREALNAMES", "0");
    ignorenofinger = new_cvar ("IGNORENOFINGER", "0");
    filesizelimit = new_cvar ("FILESIZELIMIT", "32768");
    showhome = new_cvar ("SHOWHOME", "0");
    showshell = new_cvar ("SHOWSHELL", "0");
    showmisc = new_cvar ("SHOWMISC", "0");
    showlogins = new_cvar ("SHOWLOGINS", "0");
    showlastlogin = new_cvar ("SHOWLASTLOGIN", "0");
    showaddr = new_cvar ("SHOWADDR", "0");
    showidle = new_cvar ("SHOWIDLE", "0");
    showmail = new_cvar ("SHOWMAIL", "0");
    showforward = new_cvar ("SHOWFORWARD", "0");
    showproject = new_cvar ("SHOWPROJECT", "0");
    showplan = new_cvar ("SHOWPLAN", "0");
    showpgpkey = new_cvar ("SHOWPGPKEY", "0");

    return rvalue;
}

cvar_t *
cvar_find (char *name)
{
    cvar_t *r;

    if (!cvar_head)
        return NULL;

    r = cvar_head;

    do
    {
        if (strcasecmp (name, r->name) == 0)
            return r;

        r = r->next;
    }
    while (r);

    return (cvar_t *) NULL;
}

cvar_t *
cvar_set (cvar_t * var, char *string)
{
    if (strlen (string) > CVAR_STRING_MAX - 1)
        return NULL;

    if (!var)
        return NULL;
    else
    {
        memset (var->string, 0, CVAR_STRING_MAX);
        strncpy (var->string, string, CVAR_STRING_MAX - 1);

        /* new code: ver 0.9.0: handle yes, true, on, no, false, off */

        if (strcasecmp (var->string, "yes") == 0
            || strcasecmp (var->string, "on") == 0
            || strcasecmp (var->string, "true") == 0
            || strcasecmp (var->string, "enabled") == 0)
        {
            var->value = 1;
        }
        else if (strcasecmp (var->string, "no") == 0
                 || strcasecmp (var->string, "off") == 0
                 || strcasecmp (var->string, "false") == 0
                 || strcasecmp (var->string, "disabled") == 0)
        {
            var->value = 0;
        }
        else
        {
            var->value = atoi (var->string);
        }

        return var;
    }
}

cvar_t *
cvar_set_value (cvar_t * var, int value)
{

    if (!var)
        return NULL;
    else
    {
        memset (var->string, 0, CVAR_STRING_MAX);
        snprintf (var->string, CVAR_STRING_MAX, "%d", value);
        var->value = value;
        return var;
    }
}



void
destroy_cvars (void)
{
    cvar_t *p, *r;

    if (!cvar_head)
        return;                 /* what to do? */

    p = cvar_head;

    do
    {
        r = p->next;
        free (p);
        p = r;
    }
    while (p);

    cvar_head = NULL;
}


/* parse_conf_file  -
    takes one argument, char *fname, which may either be NULL or hold the name
     of a config file to parse.
    If fname is NULL, the function tries the 4 DEFAULT_CONF files in order.
    If otherwise, the function tries to use fname as a conf file.
    Strings from the configuration file that gets read are parsed and cvar's
     are set from the results.
*/
int
parse_conf_file (char *fname)
{
    int i;
    char buf[CONF_BUF_MAX];
    char *tok, *tok2;
    FILE *fp;
    cvar_t *var;

    if (init_cvars () != 0)
    {
        perror ("malloc");
        abort ();               /* seriously */
    }

    if (fname)
    {
        if (!(fp = fopen (fname, "r")))
        {
            perror ("fopen");
            fprintf (stderr, "Could not read configuration from %s\n", fname);
            return -1;
        }
    }

    else
    {

        fp = fopen (DEFAULT_CONF_1, "r");
        if (!fp)
            fp = fopen (DEFAULT_CONF_2, "r");
        if (!fp)
            fp = fopen (DEFAULT_CONF_3, "r");
        if (!fp)
            fp = fopen (DEFAULT_CONF_4, "r");
    }

    if (!fp)
    {
        perror ("fopen");
        fprintf (stderr,
                 "Could not read a config file from any standard location.\n");
        fprintf (stderr, "Specify with bdfingerd -c\n");
        return -1;
    }

    while (1)
    {
        fgets (buf, 1024, fp);

        if (feof (fp))
            break;

        tok = strtok (buf, "= \t\r\n");
        if (tok)
        {
            if (tok[0] == '#')
                continue;

            var = cvar_find (tok);
            if (var)
            {
                tok2 = strtok (NULL, " \t\r\n");
                if (tok2)
                {
                    if (tok2[0] != '#')
                        cvar_set (var, tok2);
                    else
                        cvar_set (var, "1");
                }
                else
                    cvar_set (var, "1");
            }
            else
                fprintf (stderr, "parse_conf_file: unknown variable '%s'\n",
                         tok);
        }
    }

    fclose (fp);

    return 0;
}
