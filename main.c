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

/* bdfinger - main.c */

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

int _argc = 0;
char **_argv = NULL;

fd_set active_fd_set, read_fd_set;
int bdfinger_socket = -1;

int i_am_a_child = 0;

uid_t safeuid = 1;
gid_t safegid = 1;

int current_children = 0;
int killflag = 0;
int inetd = 0;

char *config_file = NULL;

cvar_t *repository, *tty, *pidfile, *maxchildren, *port, *safeuser,
    *timeout, *welcome, *uptime, *allowempty, *multistyle,
    *logging, *showroot, *eurodates, *matchrealnames, *forwarding,
    *filesizelimit, *ignorenofinger, *showmail, *showforward, *showproject,
    *showplan, *showpgpkey, *showhome, *showshell, *showmisc, *showlogins,
    *showlastlogin, *showaddr, *showidle;

void parse_args2 (int, char **);


/* all command line options must be mentioned here,
   with a colon after those that take arguments. */
#define OPT_CHARS 	"hikntvc:p:r:"



int
write_pid_file (char *fname)
{
    FILE *fp = NULL;

    if (!fname)
    {
        return -1;
    }

    fp = fopen (fname, "w");
    if (!fp)
        return -1;

    /* within reason, we're not going to get a single-digit PID, so
       the 3 below accounts for two digits and the \n */
    if (fprintf (fp, "%u\n", getpid ()) < 3)
        return -1;

    fclose (fp);

    return 0;
}

int
kill_pid_file (char *fname)
{
    FILE *fp = NULL;
    pid_t pid;
    int k;

    if (!fname)
        return -1;

    fp = fopen (fname, "r");
    if (!fp)
    {
        perror (fname);
        return -1;
    }

    fscanf (fp, "%u", &pid);
    fclose (fp);

    /* We're going to say that something less than 10 couldn't be the correct PID */
    if (pid < (pid_t) 10)
    {
        fprintf (stderr, "failed to read valid pid from %s.\n", fname);
        return -1;
    }

    else
    {
        k = kill (pid, SIGTERM);
        if (k != 0)
        {
            if (errno == EPERM)
                fprintf (stderr,
                         "kill: permission denied (try becoming root)\n");
            else if (errno = ESRCH)
                fprintf (stderr, "kill: process %d not found\n"
                         "See whether bdfingerd is actually already running,\n"
                         "and if not delete %s\n", pid, fname);
            return -1;
        }
        else
        {
            remove (fname);
            return 0;
        }
    }
}

void
print_help (void)
{
    printf ("bdfingerd %s   built %s\n", BDFINGER_VERSION, COMPILE_DATE);
    printf (" The Big Dumb Finger Daemon, by Lebbeous Weekley (c) 2002\n");
    printf
        ("  See the file LICENSE distributed with the source for copyright info.\n");
    printf ("Usage:\n");
    printf ("  bdfingerd [-h] [-v] [-k] [-i] [-cnprt] [ARGS]\n");
    printf ("Options:\n");
    printf ("  -h         Display this message, then exit\n");
    printf ("  -v         Display version string, then exit\n");
    printf
        ("  -i         Run the daemon in inetd mode\n");
    printf
        ("  -k         Kill the already running copy of bdfingerd, if there is one\n");
    printf
        ("  -c FILE    Parse a given configuration FILE instead of looking around\n");
    printf ("               for bdfingerd.conf\n");
    printf ("  -n         Do not log connections and notices with syslog\n");
    printf
        ("  -r FILE    Specify an alternative pid FILE in which to keep the present\n");
    printf ("               daemon's process id stored.\n");
    printf ("  -p PORT    Specify the PORT on which to run the server\n");
    printf
        ("  -t         Keep the server running in the current tty; don't put it\n");
    printf ("               in the background\n");
    printf
        ("Any options specified on the command line will always take precedence\n");
    printf ("over options specified in the configuration file.\n");
}

/*  parse_args1 - 
     this function checks *only* for the --config option, since a user-specified
     conf file must be loaded prior to interpreting any other command line options,
     since command line options should always override conf file settings.
*/

void
parse_args1 (int argc, char **argv)
{
    int c;

    opterr = 0;

    while ((c = getopt (argc, argv, OPT_CHARS)) != -1)
    {
        switch (c)
        {
        case 'c':
            config_file = optarg;
            break;
        case 'h':
            print_help ();
            exit (EXIT_SUCCESS);
        case 'v':
            printf ("bdfingerd-%s\n", BDFINGER_VERSION);
            exit (EXIT_SUCCESS);
        default:
            break;
        }
    }
}


void
parse_args2 (int argc, char **argv)
{
    int c;

    /* hopefully this resets the getopt system? */
    optind = 1;
    /* now we *do* want 'unrecognised option' messages */
    opterr = 1;

    while ((c = getopt (argc, argv, OPT_CHARS)) != -1)
    {
        if (c == -1)
            break;              /* finished */

        switch (c)
        {
        case 0:
            /* shouldn't happen in this program */
            fprintf (stderr, "getopt returned a 0. wtf?\n");
            break;
        case 'i':
            inetd = 1;
            break;
        case 'k':
            killflag = 1;
            break;
        case 'n':
            cvar_set (logging, "0");
            break;
        case 't':
            cvar_set (tty, "1");
            /* 1 as in 'true', not 1 as in tty1 */
            break;
        case 'p':
            cvar_set (port, optarg);
            break;
        case 'r':
            cvar_set (pidfile, optarg);
            break;
        case '?':
            /* Unrecognised option.  With opterr = 1, the system
               will handle printing an error message for us. */
            exit (EXIT_FAILURE);
            break;
        default:
            break;
        }

    }
}


/* MAIN */

int
main (int argc, char **argv)
{
    struct timespec ts;
    struct passwd *pw_user;



    parse_args1 (argc, argv);
    parse_conf_file (config_file);
    parse_args2 (argc, argv);
    /* realise_cvars (); */


    /* make these globally available for later */
    _argc = argc;
    _argv = argv;

    if (logging->value)
        openlog ("bdfingerd", LOG_PERROR | LOG_PID, LOG_DAEMON);


    if (maxchildren->value < 1)
    {
        fprintf (stderr, "%s: warning! Allowing unlimited children.\n"
                 "This is a Bad Idea. Check configuration.\n", argv[0]);
        cvar_set_value (maxchildren, INT_MAX);
    }
    if (timeout->value < 1)
    {
        fprintf (stderr, "%s: warning! No timeout set for connections.\n"
                 "This is a Bad Idea. Check configuration.\n", argv[0]);
    }

    /* catch_sigterm() closes the network socket and makes a note 
       if we get terminated */
    if (!inetd)
    {
        signal (SIGTERM, catch_sigterm);
        signal (SIGCHLD, catch_sigchld);
        signal (SIGHUP, catch_sighup);
    }

    /* if we were only run to kill another instance of bdfingerd, do so now */
    if (killflag)
    {
        if (kill_pid_file (pidfile->string) == -1)
        {
            destroy_cvars ();   /* free memory */
            exit (EXIT_FAILURE);
        }

        destroy_cvars ();
        exit (EXIT_SUCCESS);
    }


    if (inetd)
    {
        i_am_a_child = 1;
        strcpy (child_client, "INETD");
        do_child (fileno (stdout));
    }

    else
    {
        do_net_init (port->value);      /* LW: initialises socket listening */

        /* the only things for which bdfingerd needs root privileges are over,
           so now we drop into safeuid */
        if (getuid () == (uid_t) 0)
        {

            pw_user = getpwnam (safeuser->string);
            safeuid = pw_user->pw_uid;
            safegid = pw_user->pw_gid;

            if (setgid (safegid) != 0)
            {
                perror ("setgid");
                fprintf (stderr,
                         "%s: could not become gid (%d). check configuration.\n",
                         argv[0], safegid);
                close (bdfinger_socket);
                destroy_cvars ();
                exit (EXIT_FAILURE);
            }
            if (setuid (safeuid) != 0)
            {
                perror ("setuid");
                fprintf (stderr,
                         "%s: could not become uid '%s' (%d). check configuration.\n",
                         argv[0], safeuser->string, safeuid);
                close (bdfinger_socket);
                destroy_cvars ();
                exit (EXIT_FAILURE);
            }
        }

        /* detach the process from its terminal, unless otherwise specified by
           command-line or conf file options */
        if (!tty->value)
        {
            if (daemon (0, 0) < 0)
            {
                perror ("daemon");
                destroy_cvars ();
                exit (EXIT_FAILURE);
            }
        }

        /* now we've call everything that has the potential to change our pid, so
           writing the pid_file is now going to be accurate. */

        if (write_pid_file (pidfile->string) == -1)
        {
            clog (LOG_ERR, "write_pid_file failed. Check configuration.\n");
        }


        ts.tv_sec = 0;
        ts.tv_nsec = 200000000; /* basically 1/5 of a second */

        while (1)
        {
            /* LW: sleep every so often,keeps CPU usage down */
            nanosleep (&ts, (struct timespec *) NULL);

            /* answer network requests */
            if (current_children <= maxchildren->value)
                do_net_check (bdfinger_socket);
            else
            {
		/* FIXME: kind of useless unless we're running in a tty */
                fprintf (stderr, "too many children. waiting\n");
            }
        }
    }

    /* no way we'll ever actually get here */
    return 0;
}
