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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <paths.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "bdfinger.h"


/* mail.c - includes functions to return time_t's for when a user's mail
             was last read, and when mail last arrived */


/* _PATH_MAILDIR is usually defined in paths.h.  Is /var/mail the best
   guess for systems that don't have _PATH_MAILDIR ? */
#ifndef _PATH_MAILDIR
#define _PATH_MAILDIR	"/var/mail"
#endif

struct stat *
stat_mailbox (char *username)
{
    struct stat *buf;
    char *filename;

    if (!username || strlen (username) < 1)
        return NULL;

    filename = malloc (strlen (_PATH_MAILDIR) + strlen (username) + 2);
    if (!filename)
        return NULL;

    buf = malloc (sizeof (struct stat));
    if (!buf)
        return NULL;

    sprintf (filename, "%s/%s", _PATH_MAILDIR, username);

    if (stat (filename, buf) != 0)
        return NULL;

    else
        return buf;
}
