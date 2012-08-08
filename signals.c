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
  
    The author may be reached via lebbeous@gmail.com
*/

/* bdfinger - signals.c */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <syslog.h>

#include "bdfinger.h"


void parse_args2 (int, char **);
extern int _argc;
extern char **_argv;
extern char *config_file;

/* this is my function to catch SIGTERM */
void
catch_sigterm (int sig)
{

    time_t t;

    if (logging->value)
    {
        time (&t);

        clog (LOG_ERR, "(%s) cleaning up, caught SIGTERM at %s",
              i_am_a_child ? "child" : "parent", asctime (localtime (&t)));
    }

    /* LW: close the network socket, the nice thing to do */
    if (bdfinger_socket != -1)
        close (bdfinger_socket);

    if (strlen (pidfile->string) > 0 && !i_am_a_child)
        remove (pidfile->string);

    closelog ();                /* not especially necessary */

    destroy_cvars ();           /* free a lot of memory */

    exit (2);                   /* this exit status represents sigterm to us */
}

void
catch_sigchld (int sig)
{
    int rv;

    if (!i_am_a_child)
    {
        wait (&rv);
        fprintf (stderr, "child exited with %d.\n", rv);
        current_children--;
    }
}

/* this means that when bdfingerd gets a SIGHUP, it will reparse its
    configuration file for changes in parameters */
void
catch_sighup (int sig)
{
    if (!i_am_a_child)
    {
        if (parse_conf_file (config_file) == 0)
            clog (LOG_NOTICE, "(parent) SIGHUP received, re-read config\n");
        else
            clog (LOG_ERR,
                  "(parent) SIGHUP received, but config re-read FAILED.\n");

        /* re-parse command line options, since they should always take
           precedent over conf file options, even after a SIGHUP */
        parse_args2 (_argc, _argv);
    }
}
