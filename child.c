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

/* child.c for bdfinger */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>

#include "bdfinger.h"

int wideflag = 0;
int child_global_sock = -1;
int receiving_input;
int forwardquery = 0;

/* the reason we handle userinfo in the child process is so that
   the bdfinger daemon will be aware of changes to /etc/passwd 
   during the lifetime of the parent process instead of being static */

struct userinfo_s *userinfo;

void
do_child (int sock)
{

    char username[MAX_USERNAME];
    char thirdpartybuf[1024];
    int thirdpartysock;
    char *thirdpartyname;
    struct sockaddr_in thirdparty;
    int i;
    char c;
    int err, sl;

    struct userinfo_s *u;
    struct userinfo_s *oldu;
    entry2_t *logins, *lp, *oldlp;

    child_global_sock = sock;


    if (logging->value)
    {
        openlog ("bdfingerd", LOG_PID, LOG_DAEMON);
    }

    receiving_input = 1;

    if (timeout->value > 0)
    {
        signal (SIGALRM, child_catch_sigalrm);
        alarm (timeout->value); /* raise a SIGALRM after timeout period */
    }


    memset (username, 0, MAX_USERNAME);


    wideflag = 0;

    child_read_input (username);

    receiving_input = 0;

    userinfo = search_passwd_file ();
    if (!userinfo)
    {
        cprintf (sock, "Fatal error: No access to user database\n");
        child_exit (EXIT_FAILURE);
    }

    /* FIXME: replace this stuff with something better and that checks
       welcome and uptime independently */
    /* welcome info here */
    if (welcome->value)
    {
        /* pass uptime->value to this function as a boolean. if true,
           print uptime in the banner, otherwise don't */
        cputs (sock, banner_string (uptime->value));
    }

    if (forwardquery)
    {
        if (!forwarding->value)
        {
            cprintf (sock, "Forwarding not allowed\n");
            clog (LOG_NOTICE, "%s attempted forwarding\n", child_client);
            child_exit (EXIT_FAILURE);
        }
        else
        {
            clog (LOG_NOTICE, "%s forwarded query %s\n", child_client,
                  username);
            /* scan the query string backwards to find the last '@' */
            for (i = strlen (username) - 1; i >= 0; i--)
            {
                if (username[i] == '@')
                {
                    thirdpartyname = &username[i + 1];

                    /* prepare a fresh socket for third party connection */
                    thirdpartysock = socket (PF_INET, SOCK_STREAM, 0);
                    if (thirdpartysock < 0)
                    {
                        cprintf (sock,
                                 "Couldn't create socket for third party host %s\n",
                                 thirdpartyname);
                        break;
                    }

                    /* Connect to the third party server. */
                    init_sockaddr (&thirdparty, thirdpartyname, 79);
                    if (connect
                        (thirdpartysock, (struct sockaddr *) &thirdparty,
                         sizeof (thirdparty)) < 0)
                    {
                        cprintf (sock, "Couldn't connect to %s\n",
                                 thirdpartyname);
                        break;
                    }

                    cprintf (sock, "[%s]\n", &username[i + 1]);

                    /* if we got a /W from our client, we should pass it along to
                       our next host, before the rest of the query, as specified
                       by RFC 1288. */
                    if (wideflag)
                    {
                        if (write (thirdpartysock, "/W ", 3) < 3)
                        {
                            cprintf (sock,
                                     "Write error to the remote server\n");
                            close (thirdpartysock);
                            break;
                        }
                    }
                    /* slap a CRLF at the end of the token we want to pass along,
                       then send it. */
                    username[i] = '\r';
                    username[i + 1] = '\n';
                    if (write (thirdpartysock, username, i + 2) < i + 2)
                    {
                        cprintf (sock, "Write error to remote server\n");
                        close (thirdpartysock);
                        break;
                    }
                    /* always recycle your variables :) */
                    while ((i =
                            read (thirdpartysock, thirdpartybuf, 1023)) > 0)
                    {
                        thirdpartybuf[i] = '\0';
                        cprintf (sock, "%s", thirdpartybuf);
                    }
                    close (thirdpartysock);
                    /* forward here */
                    break;
                }
            }
            child_exit (EXIT_SUCCESS);
        }
    }

    if (strlen (username) == 0)
    {
        if (allowempty->value && showlogins->value)
        {
            clog (LOG_NOTICE, "%s fingered all users\n", child_client);
            list_logins (sock);
            child_exit (EXIT_SUCCESS);
        }
        else
        {
            clog (LOG_NOTICE, "%s tried to finger all users\n", child_client);
            cprintf (sock, "Must specify user name\n");
            child_exit (EXIT_SUCCESS);  /* this is not really a failure */
        }
    }

    u = match_passwd_entry (username);

    if (!u)
    {
        clog (LOG_NOTICE, "%s query '%s' failed\n", child_client, username);
        cprintf (sock, "No information is available for '%s'\n", username);
    }

    else
    {

        clog (LOG_NOTICE, "%s fingered '%s'\n", child_client, username);

        while (u)
        {
            print_user_paragraph (sock, u);

            oldu = u;
            u = u->next;
            free (oldu);

            if (u)
                cprintf (sock, "\n");   /* get ready for the next one */
        }
    }

    child_exit (EXIT_SUCCESS);
}


void
child_catch_sigalrm (int sig)
{
    if (receiving_input)
    {
        clog (LOG_WARNING,
              "%s timed out without making a request.\n", child_client);
        child_exit (EXIT_FAILURE);
    }
}

void
child_exit (int code)
{

    struct userinfo_s *u, *old;

    /* syslogd stuff */
    if (logging->value)
        closelog ();


    /* this frees the memory used in parsing the passwd
       file, if it has been done */
    if (userinfo)
    {
        u = userinfo;
        do
        {
            old = u;
            u = u->next;
            free (old);
        }
        while (u);
    }

    if (child_global_sock > -1)
        close (child_global_sock);

    if (!inetd)
        sleep (1);

    exit (code);
}

void
child_read_input (char *buf)
{
    int err;
    char c;
    int i = 0;
    int oursock;


    /* We read from oursock as a file descriptor. If we're a standalone server,
       set it to child_global_sock which was assigned to this child process by
       the parent after receiving a new client connection. Otherwise we just want
       stdin */

    if (inetd)
        oursock = fileno (stdin);
    else
        oursock = child_global_sock;

    do
    {
        err = read (oursock, &c, 1);
        if (err < 0)
        {
            receiving_input = 0;
            clog (LOG_WARNING,
                  "%s connected, but read error (%d) suggests scan.\n",
                  child_client, err);
            child_exit (EXIT_FAILURE);
        }
        else if (err == 1)
        {
            if ((i < MAX_USERNAME - 1)
                && (isalpha (c) || isdigit (c) || (c == '_')
                    || (c == '.') || (c == '-')))
                buf[i++] = c;
            else if (c == '@')
            {
                forwardquery = 1;
                buf[i++] = c;
            }
            else if (c == '/')
            {
                read (oursock, &c, 1);
                if (toupper (c) == 'W')
                    wideflag = 1;
                else
                {
                    receiving_input = 0;
                    cprintf (oursock,
                             "Invalid input - option /%c unrecognised\n", c);
                    if (isprint (c))
                        clog (LOG_NOTICE,
                              "%s sent unrecognised option '/%c'\n",
                              child_client, c);
                    else
                        clog (LOG_WARNING,
                              "%s sent unrecognised, unprintable option /0x%02x\n",
                              child_client, c);

                    child_exit (EXIT_FAILURE);
                }
            }

            else if (c == '\r')
            {
                read (oursock, &c, 1);
                if (c != '\n')
                {
                    receiving_input = 0;
                    clog (LOG_WARNING,
                          "%s sent invalid input - CR without LF\n",
                          child_client);
                    child_exit (EXIT_FAILURE);
                }

                /* success */
                break;
            }

            else if (c == '\n')
            {
                receiving_input = 0;
                fprintf (stderr, "lr no cr\n");
                clog (LOG_WARNING, "%s sent invalid input - early LF",
                      child_client);
                child_exit (EXIT_FAILURE);
            }

        }
        else
        {
            receiving_input = 0;
            clog (LOG_WARNING,
                  "%s sent invalid input - unexpected EOF\n", child_client);
            child_exit (EXIT_FAILURE);
        }

    }
    while (err >= 0);

}

/* that's c-log, not 'clog' like the dancing ;-) */
int
clog (int pri, char *buf, ...)
{
    va_list argptr;
    char str[4096];
    int count;

    str[0] = '\0';
    va_start (argptr, buf);
    count = vsnprintf (str, 4096, buf, argptr);

    if (logging->value)
        syslog (pri, str);

    va_end (argptr);
}
