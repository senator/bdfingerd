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

/* format.c for bdfinger */

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

extern int wideflag;
extern int child_global_sock;
extern int receiving_input;
extern int forwardquery;
extern struct userinfo_s *userinfo;


/* begin */

int
cputs (int fd, char *s)
{
    write (fd, s, strlen (s));
}

int
cputc (int fd, char c)
{

    static char *_crlf = "\r\n";
    static char caret = '^';

    if (c == '\n')              /* need to throw in that CR too */
    {
        write (fd, _crlf, 2);
    }

    else if (c == '\r')
        ;                       /* skip CR's */

    else if ((c < 32) && (c != 9))      /* tab */
    {
        write (fd, &caret, 1);
        c += 'A';
        c -= 1;
        write (fd, &c, 1);
    }

    else
        write (fd, &c, 1);

}

/* the cprintf function -

	WARNING: the formatted string result had better be <= 4096 bytes including the
		null terminator
*/

int
cprintf (int fd, const char *format, ...)
{
    va_list argptr;
    char str[4096];
    int i, count;

    str[0] = '\0';
    va_start (argptr, format);
    count = vsprintf (str, format, argptr);


    for (i = 0; i < strlen (str); i++)
        cputc (fd, str[i]);

    va_end (argptr);
    return count;
}

/* if DEBUG _is_ defined, dprintf is #define'd to cprintf */
#ifndef DEBUG
int
dprintf (int fd, const char *format, ...)
{
    return 0;
}
#endif /* DEBUG */

int
print_special_file (int fd, struct userinfo_s *ui, char *filename,
                    char *preface)
{

    int ufd, num, i, totalsize;
    int newlined = 0;
    char path1[PATH_MAX];
    char path2[PATH_MAX];
    char path3[PATH_MAX];
    char buf[128];

    snprintf (path1, PATH_MAX, "%s/%s/%s", repository->string,
              ui->name, filename);
    snprintf (path2, PATH_MAX, "%s/%s/.%s", repository->string,
              ui->name, filename);
    snprintf (path3, PATH_MAX, "%s/.%s", ui->homedir, filename);

    ufd = open (path1, O_RDONLY);
    if (ufd == -1)
        ufd = open (path2, O_RDONLY);
    if (ufd == -1)
        ufd = open (path3, O_RDONLY);
    if (ufd == -1)
        return -1;

    else
    {
        cprintf (fd, "%s", preface);

        totalsize = 0;
        do
        {
            num = read (ufd, buf, 128);
            for (i = 0; i < num; i++)
            {
                if (totalsize >= filesizelimit->value)
                    break;

                if (buf[i] == '\n')
                {
                    /* This is a very ugly kludge.
                       It guarantees .project and .forward to be
                       only one line. */
                    if (!strchr (preface, '\n'))
                        break;
                    else
                        newlined = 1;
                }
                else if (!isspace (buf[i]))
                    newlined = 0;
                cputc (fd, buf[i]);
                totalsize++;
            }
        }
        while (num >= 1);

        if (!newlined)
            cputc (fd, '\n');
        close (ufd);
        return 0;
    }
}

int
check_nofinger (struct userinfo_s *ui)
{
    char path1[PATH_MAX];
    char path2[PATH_MAX];
    char path3[PATH_MAX];
    struct stat sb;

    snprintf (path1, PATH_MAX, "%s/%s/nofinger", repository->string,
              ui->name);
    snprintf (path2, PATH_MAX, "%s/%s/.nofinger", repository->string,
              ui->name);
    snprintf (path3, PATH_MAX, "%s/.nofinger", ui->homedir);

    if (stat (path1, &sb) == 0)
        return 1;               /* true */
    else if (stat (path2, &sb) == 0)
        return 1;
    else if (stat (path3, &sb) == 0)
        return 1;
    else
        return 0;               /* false */

}


char *
banner_string (int upt)
{
    char hn[33];
    static char buffer[84];

    if (gethostname (hn, 33) == -1)
    {
        if (errno != ENAMETOOLONG)
            hn[0] = '\0';
    }

    if (upt)
        snprintf (buffer, 84, "Welcome to %s!  %s  %s\r\n\n",
                  hn, clock_string (), uptime_string ());
    else
        snprintf (buffer, 84, "Welcome to %s!  %s\r\n\n", hn,
                  clock_string ());

    return buffer;
}

char *
clock_string (void)
{
    time_t now;
    struct tm *timep;
    static char cstring[16] = "";
    const char *format = "%a %H:%M %Z";

    time (&now);
    timep = localtime (&now);

    if (timep)
        strftime (cstring, 16, format, timep);

    return cstring;
}

/* returns a pointer to malloc'd string, which should be free when done with use */
char *
time_string (time_t t)
{
    struct tm *timep;
    char *str;
    int thisyear;
    time_t now;


    time (&now);
    timep = localtime (&now);
    thisyear = timep->tm_year;

    /* this is meant to hold something in the form
       of "Tue 10 Apr 2001 12:34 (BRZST)", which is the longest possible string */
    str = malloc (ENTRY2_MAXTIME);

    if (!str)
        return NULL;

    else
    {
        timep = localtime (&t);
        if (timep->tm_year == thisyear)
            strftime (str, ENTRY2_MAXTIME,
                      eurodates->
                      value ? EURO_DATE_FORMAT1 : AMER_DATE_FORMAT1, timep);
        else
            strftime (str, ENTRY2_MAXTIME,
                      eurodates->
                      value ? EURO_DATE_FORMAT2 : AMER_DATE_FORMAT2, timep);

        return str;
    }
}

char *
uptime_string (void)
{

    static char upt_string[20] = "";
    time_t now;
    struct tm *timep;
    int pos = 0;
    int upsecs, upmins, uphours, updays;
    double upvalue;
    FILE *fp;


    fp = fopen ("/proc/uptime", "r");
    if (!fp)
        return upt_string;
    if (fscanf (fp, "%lf", &upvalue) < 1)
    {
        fclose (fp);
        return upt_string;
    }
    fclose (fp);

    upsecs = (int) upvalue;
    updays = upsecs / (60 * 60 * 24);

    upmins = upsecs / 60;
    uphours = upmins / 60;
    uphours %= 24;
    upmins %= 60;

    pos += sprintf (upt_string, "up ");
    if (updays)
        pos +=
            sprintf (&upt_string[pos], "%d day%s, ", updays,
                     updays == 1 ? "" : "s");

    if (uphours)
        pos += sprintf (&upt_string[pos], "%d:%02d", uphours, upmins);
    else
        pos += sprintf (&upt_string[pos], "%d min", upmins);


    return upt_string;

}
