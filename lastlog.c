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

/* bdfingerd - lastlog.c - deals with determining last login time for users */

#include <stdio.h>
#include <lastlog.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "bdfinger.h"


int lastlogin_string (char *, struct lastlog *);



/* this function is only used when displaying the verbose
   version of a particular users information, not in the 
   'finger everybody' situation, so it only needs to handle
   entry2_t's and not entry_t's */

int
get_lastlogin (struct userinfo_s *user, entry2_t * logins)
{

    loff_t pos;
    int fd;
    struct lastlog last;
    entry2_t *p, *p2;


    if (!user)
        return -1;

    /* start with blank string */
    user->lastlogin[0] = '\0';

    fd = open (_PATH_LASTLOG, O_RDONLY, 0);

    if (fd == -1)
        return -1;

    pos = (loff_t) user->uid * sizeof (struct lastlog);

    if (lseek (fd, pos, L_SET) != pos)
    {
        close (fd);
        return -1;
    }

    if (read (fd, &last, sizeof (struct lastlog)) != sizeof (struct lastlog))
    {
        close (fd);
        return 0;               /* will just report 'never logged in' */
    }

    close (fd);

    if (last.ll_time == 0)
        return 0;

    else if (!logins)
    {
        lastlogin_string (user->lastlogin, &last);
        return 0;
    }

    else
    {
        for (p = logins; p; p = p->next)
        {
            if (p->clogin < last.ll_time)
            {
                for (p2 = logins; p2; p2 = p2->next)
                {
                    if (strncmp (p2->tty, last.ll_line, UT_LINESIZE) == 0)
                        return -1;      /* say nothing */
                }
                lastlogin_string (user->lastlogin, &last);
                return 0;
            }
        }
    }


    return -1;
}



/* for internal use only within this module, this function formats a
   'Sun  5 Sep 18:01 (EDT) at ttyp0 from nothing.but.net' style string
   to the variable 'str' from the data contained in 'last' */

int
lastlogin_string (char *str, struct lastlog *last)
{

    time_t now;
    int thisyear;
    struct tm *timep;
    int cnt;

    if (!str || !last)
        return -1;

    time (&now);
    timep = localtime (&now);
    thisyear = timep->tm_year;

    timep = localtime (&(last->ll_time));
    if (timep->tm_year == thisyear)
        cnt = strftime (str, MAXLASTLOGIN,
                        eurodates->
                        value ? EURO_DATE_FORMAT1 : AMER_DATE_FORMAT1, timep);
    else
        cnt = strftime (str, MAXLASTLOGIN,
                        eurodates->
                        value ? EURO_DATE_FORMAT2 : AMER_DATE_FORMAT2, timep);

    if (strlen (last->ll_host) > 24 && showaddr->value)
        snprintf (str + cnt, MAXLASTLOGIN - cnt - 1, " on %s\n  from %s",
                  last->ll_line, last->ll_host);
    else if (strlen (last->ll_host) > 0 && showaddr->value)
        snprintf (str + cnt, MAXLASTLOGIN - cnt - 1, " on %s from %s",
                  last->ll_line, last->ll_host);
    else
        snprintf (str + cnt, MAXLASTLOGIN - cnt - 1, " on %s", last->ll_line);


    return 0;
}
