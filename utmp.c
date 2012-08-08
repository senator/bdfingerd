/*
 * Big Dumb Finger Daemon - a secure, highly configurable finger daemon
 * Copyright (C) 2002 Lebbeous Weekley
 * 
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 * 
 * The author may be reached via lebbeous@gmail.com 
 */

#include <stdio.h>
#include <stdarg.h>
#include <paths.h>
#include <utmp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "bdfinger.h"

extern int child_global_sock;
extern int wideflag;

userinfo_t *match_uid_in_list (userinfo_t * ui, uid_t uid);



void
list_logins (int sock)
{

    struct utmp *uptr;
    int i = 0, j;
    entry_t *head = NULL;
    entry_t *p = NULL, *old = NULL;
    char *tstring, *s2 = NULL, *tok = NULL;
    userinfo_t *u, *oldu;
    userinfo_t *namelist = NULL, *np, *oldnp;
    int match = 0;

    /*
     * minimum values 
     */
    int maxname = 5, maxtty = 3, maxrname = 4, maxaddr = 4;
    int addrlimit;


    /*
     * if MULTISTYLE cvar is 'long', the paragraph (or 'wide') style is
     * used no matter what 
     */
    if (strcasecmp (multistyle->string, "long") == 0)
        wideflag = 1;

    setutent ();


    while ((uptr = getutent ()) != NULL)
    {
        if (!uptr->ut_name[0])
            continue;

        if ((strcmp (uptr->ut_name, "root") == 0) && (showroot->value == 0))
            continue;
#ifdef USER_PROCESS
        if (uptr->ut_type != USER_PROCESS)
            continue;
#endif

        u = match_passwd_entry (uptr->ut_name);

        /*
         * if this happens here, it's probably because the user has a
         * nofinger file (match_passwd_entry() calls check_nofinger()) 
         */
        if (!u)
            continue;

        /*
         * ok, now we have an entry from utmp and a user to match 
         */
        if (!wideflag)
        {

            /*
             * note that this section adds to the linked list of entry_t's
             * preparing for non-wide style only. It does NOT print out
             * anything or do more than one login at a time, so there will
             * of course have to be a second if(!wideflag) later to handle
             * that, and of course two separate if(wideflag)'s to do the
             * equivalent thing.
             */
            if (!head)
            {
                head = malloc (sizeof (entry_t));
                if (!head)
                {
                    return;
                }
                memset (head, 0, sizeof (entry_t));
                p = head;
                dprintf (sock, "head alloc'd\n");
            }
            else
            {
                p->next = malloc (sizeof (entry_t));
                p = p->next;
                if (!p)
                {
                    return;
                }
                memset (p, 0, sizeof (entry_t));
                dprintf (sock, "node alloc'd\n");
            }


            p->timep = malloc (sizeof (struct tm));
            if (p->timep)
                memcpy (p->timep, localtime (&(uptr->ut_time)),
                        sizeof (struct tm));
            else
                return;

            tstring = login_time_string (p->timep, ENTRY_MAXTSTRING);
            if (!tstring)
                return;
            else
                strncpy (p->tstring, tstring, ENTRY_MAXTSTRING + 1);



            strncpy (p->rname, u->realname, ENTRY_MAXRNAME);
            do
            {
                oldu = u;
                u = u->next;
                free (oldu);
            }
            while (u);

            if (strlen (p->rname) > maxrname)
                maxrname = strlen (p->rname);


            strncpy (p->name, uptr->ut_name, ENTRY_MAXNAME);
            if (strlen (p->name) > maxname)
                maxname = strlen (p->name);
            strncpy (p->tty, uptr->ut_line, ENTRY_MAXTTY);
            if (strlen (p->tty) > maxtty)
                maxtty = strlen (p->tty);
            strncpy (p->addr, uptr->ut_host, ENTRY_MAXADDR);
            if (strlen (p->addr) > maxaddr)
                maxaddr = strlen (p->addr);

            dprintf (sock, "added %s on %s to list\n", p->name, p->tty);
            stat_tty (p, 1);
            i++;

        }

        else
        {                       /* if wideflag */

            if (!match_uid_in_list (namelist, u->uid))
            {


                if (namelist == (userinfo_t *) NULL)
                {
                    namelist = np = malloc (sizeof (userinfo_t));
                    if (namelist == (userinfo_t *) NULL)
                        return;
                    memset (namelist, 0, sizeof (userinfo_t));
                }
                else
                {
                    /* gets at the last link in the linked list */
                    for (np = namelist; np->next; np = np->next);

                    np->next = (userinfo_t *) malloc (sizeof (userinfo_t));

                    if (np->next == (userinfo_t *) NULL)
                        return;
                    memset (np->next, 0, sizeof (userinfo_t));
                    np = np->next;
                }

                memcpy (np, u, sizeof (userinfo_t));
                u->next = (userinfo_t *) NULL;  /* likely unnecessary */

                i++;

                /* advances through each link in the linked list */
                for (np = namelist; np; np = np->next)
                    dprintf (sock, "%d %s %s\n", i, np->name, np->realname);
            }
        }

    }

    /* we're done with utmp here, and it must be closed so that get_logins can be called */
    endutent ();

    /* prepare to traverse the list we've created and print it out nicely */
    p = head;
    np = namelist;
    j = 0;

    if (i && (!wideflag))
    {
        cprintf (sock, "Login ");
        for (j = 0; j < maxname - 4; j++)
            cprintf (sock, " ");
        cprintf (sock, "Name ");
        for (j = 0; j < maxrname - 3; j++)
            cprintf (sock, " ");
        cprintf (sock, " TTY ");
        for (j = 0; j < maxtty - 2; j++)
            cprintf (sock, " ");
        cprintf (sock, "Since ");
        for (j = 0; j < ENTRY_MAXTSTRING - 4; j++)
            cprintf (sock, " ");
        if (showidle->value)
        {
            cprintf (sock, "Idle ");
            for (j = 0; j < ENTRY_MAXISTRING - 3; j++)
                cprintf (sock, " ");
        }
        if (showaddr->value)
        {
            cprintf (sock, "From");
        }

        cprintf (sock, "\n");

        if (showidle->value)
            addrlimit =
                80 - (maxname + 2 + maxrname + 3 + maxtty + 2 +
                      ENTRY_MAXTSTRING + 2 + ENTRY_MAXISTRING + 2);
        else
            addrlimit =
                80 - (maxname + 2 + maxrname + 3 + maxtty + 2 +
                      ENTRY_MAXTSTRING + 2);

        while (p)
        {
            cprintf (sock, "%s", p->name);
            for (j = 0; j < (maxname - strlen (p->name)) + 2; j++)
                cprintf (sock, " ");
            cprintf (sock, "%s", p->rname);
            for (j = 0; j < (maxrname - strlen (p->rname)) + 2; j++)
                cprintf (sock, " ");
            cprintf (sock, "%s%s", p->msg ? " " : "*", p->tty);
            for (j = 0; j < (maxtty - strlen (p->tty)) + 2; j++)
                cprintf (sock, " ");
            cprintf (sock, "%s  ", p->tstring);

            if (showidle->value)
                cprintf (sock, "%s  ", p->istring);
            if (showaddr->value)
            {
                for (j = 0; j < addrlimit && p->addr[j]; j++)
                    cputc (sock, p->addr[j]);
            }
            cprintf (sock, "\n");

            old = p;
            p = p->next;
            dprintf (sock, "%s freed\n", (old == head) ? "head" : "node");
            free_entry (old);
        }
    }

    else if (i > 0)             /* && wideflag */
    {
        dprintf (sock, "wideflag with people logged on.\n");

        if ((np = namelist) != (userinfo_t *) NULL)
        {
            do
            {

                print_user_paragraph (sock, np);
                if (np->next)
                    cprintf (sock, "\n");

                oldnp = np;
                np = np->next;
                if (oldnp)
                {
                    dprintf (sock, "freeing\n");
                    free (oldnp);
                }
            }
            while (np);
        }
    }

    else
    {
        cprintf (sock, "No one logged on.\n");
    }


}

entry2_t *
get_logins (char *name)
{

    entry2_t *head = NULL;
    entry2_t *p, *old;

    struct utmp *uptr;
    time_t now;
    char *tstring = NULL;


    time (&now);

    setutent ();

    while ((uptr = getutent ()) != NULL)
    {
        if (!uptr->ut_name[0])
            continue;
#ifdef USER_PROCESS
        if (uptr->ut_type != USER_PROCESS)
            continue;
#endif

        /*
         * FIXME: this strcmp may have to be dealt with later for the sake 
         * of 'name' being a truncated version of the whole username, or
         * maybe even case issues 
         */
        if (strcmp (uptr->ut_name, name) == 0)
        {
            if (!head)
            {
                p = head = malloc (sizeof (entry2_t));
                if (!p)
                {
                    perror ("malloc");
                    return NULL;
                }
                memset (p, 0, sizeof (entry2_t));
                p->next = NULL;
            }
            else
            {
                p->next = malloc (sizeof (entry2_t));
                if (!p->next)
                {
                    perror ("malloc");
                    return head;
                }
                memset (p->next, 0, sizeof (entry2_t));
                p = p->next;
                p->next = NULL;
            }


            /*
             * this block allocation scheme will prevent inefficient,
             * possibly memory-wasting multiple calls to malloc(), though
             * as a trade off its a bit hard to understand at first. just
             * free p->base and p itself when done 
             */
            p->base = malloc (sizeof (struct tm) +
                              +UT_NAMESIZE + 1 + UT_LINESIZE + 1 +
                              UT_HOSTSIZE + 1);

            if (p->base)
            {
                p->timep = (struct tm *) p->base;
                p->name = (char *) p->timep + sizeof (struct tm);
                p->tty = p->name + UT_NAMESIZE + 1;
                p->addr = p->tty + UT_LINESIZE + 1;
            }
            else
                return NULL;


            strncpy (p->name, uptr->ut_name, UT_NAMESIZE);
            strncpy (p->tty, uptr->ut_line, UT_LINESIZE);
            strncpy (p->addr, uptr->ut_host, UT_HOSTSIZE);

            if (p->timep)
                memcpy (p->timep, localtime (&(uptr->ut_time)),
                        sizeof (struct tm));
            else
                return NULL;

            tstring = login_time_string (p->timep, ENTRY2_MAXTIME);
            if (tstring)
                strcpy (p->tstring, tstring);

            p->clogin = uptr->ut_time;

            stat_tty (p, 2);

        }
    }

    endutent ();

    return head;
}


char *
login_time_string (struct tm *timep, int which)
{
    struct tm *nowp;
    time_t now;
    static char buf[ENTRY_MAXTSTRING + 1];
    static int count = 0;
    int ed;


    ed = eurodates->value;

    if (!timep)
        return NULL;

    time (&now);
    nowp = localtime (&now);

    if (!nowp)
        return NULL;


    if (which == ENTRY_MAXTSTRING)
    {
        if (nowp->tm_year != timep->tm_year)
        {
            strftime (buf, ENTRY_MAXTSTRING + 1,
                      ed ? "%e %b  %Y" : "%b %e  %Y", timep);
        }
        else if (nowp->tm_mon != timep->tm_mon)
        {
            strftime (buf, ENTRY_MAXTSTRING + 1,
                      ed ? "%e %b %H:%M" : "%b %e %H:%M", timep);
        }
        else if (nowp->tm_mday == timep->tm_mday)
        {
            strftime (buf, ENTRY_MAXTSTRING + 1, "Today  %H:%M", timep);
        }
        else if ((nowp->tm_mday < timep->tm_mday + 7)
                 && (nowp->tm_wday >= timep->tm_wday))
        {
            strftime (buf, ENTRY_MAXTSTRING + 1, "%a    %H:%M", timep);
        }
        else
        {
            strftime (buf, ENTRY_MAXTSTRING + 1,
                      ed ? "%e %b %H:%M" : "%b %e %H:%M", timep);
        }
    }
    else
    {
        /*
         * ex: "Sun 5 Sep 18:01 (EDT)" if in the same year, or "Sun 5 Sep
         * 1999" if not 
         */

        if (nowp->tm_year == timep->tm_year)
        {
            strftime (buf, ENTRY2_MAXTIME,
                      ed ? EURO_DATE_FORMAT1 : AMER_DATE_FORMAT1, timep);
        }
        else
            strftime (buf, ENTRY2_MAXTIME,
                      ed ? EURO_DATE_FORMAT2 : AMER_DATE_FORMAT2, timep);
    }

    return buf;
}

int
stat_tty (void *ent, int which)
{
    struct stat st;
    static char linebuf[UT_LINESIZE + 6] = "";
    char buf[32] = "";
    time_t now;
    int isecs, imins, ihours, idays;
    entry_t *ent1;
    entry2_t *ent2;
    int pos = 0;

    if (!ent)
        return -1;

    ent1 = (entry_t *) ent;
    ent2 = (entry2_t *) ent;


    if (which == 1)
    {                           /* assume ent is entry_t */
        snprintf (linebuf, UT_LINESIZE + 6, "/dev/%s", ent1->tty);
        if (stat (linebuf, &st) == 0)
        {
            if (st.st_mode & S_IWGRP)
                ent1->msg = 1;

            if (!time (&now))
                return -1;

            if (now > st.st_atime)
            {
                isecs = now - st.st_atime;
                imins = isecs / 60;
                ihours = imins / 60;
                idays = ihours / 24;
                isecs %= 60;
                imins %= 60;
                ihours %= 24;
                idays %= 999;   /* FIXME: necessary to limit to 3 digits? */

                if (idays > 99)
                    snprintf (buf, ENTRY_MAXISTRING + 1, "%ddays", idays);
                else if (idays)
                    snprintf (buf, ENTRY_MAXISTRING + 1, "%2dd %2dh", idays,
                              ihours);
                else if (ihours)
                    snprintf (buf, ENTRY_MAXISTRING + 1, "%2dh %2dm", ihours,
                              imins);
                else if (imins)
                    snprintf (buf, ENTRY_MAXISTRING + 1, "%2dm %2ds", imins,
                              isecs);
                else if (isecs)
                    snprintf (buf, ENTRY_MAXISTRING + 1, " %2d sec", isecs);
                else
                    snprintf (buf, ENTRY_MAXISTRING + 1, "!error! ");
            }
            else
                snprintf (buf, ENTRY_MAXISTRING + 1, " --  --");
        }
        strcpy (ent1->istring, buf);
        return 0;               /* success */
    }

    else if (which == 2)
    {                           /* assume ent is entry2_t */
        snprintf (linebuf, UT_LINESIZE + 6, "/dev/%s", ent2->tty);

        if (stat (linebuf, &st) == 0)
        {
            if (st.st_mode & S_IWGRP)
                ent2->msg = 1;

            if (!time (&now))
                return -1;

            if (now > st.st_atime)
            {
                isecs = now - st.st_atime;
                imins = isecs / 60;
                ihours = imins / 60;
                idays = ihours / 24;
                isecs %= 60;
                imins %= 60;
                ihours %= 24;
                idays %= 999;   /* FIXME: necessary to limit to 3 digits? */

                if (idays)
                {
                    pos =
                        snprintf (buf, ENTRY2_MAXIDLE, "%d day%s", idays,
                                  idays == 1 ? "" : "s");
                    if (ihours)
                        snprintf (&buf[pos], ENTRY2_MAXIDLE - pos,
                                  ", %d hour%s", ihours,
                                  ihours == 1 ? "" : "s");
                }
                else if (ihours)
                {
                    pos =
                        snprintf (buf, ENTRY2_MAXIDLE, "%d hour%s", ihours,
                                  ihours == 1 ? "" : "s");
                    if (imins)
                        snprintf (&buf[pos], ENTRY2_MAXIDLE - pos,
                                  ", %d minute%s", imins,
                                  imins == 1 ? "" : "s");
                }
                else if (imins)
                {
                    pos = snprintf (buf, ENTRY2_MAXIDLE, "%d minute%s",
                                    imins, imins == 1 ? "" : "s");
                    if (isecs)
                        snprintf (&buf[pos], ENTRY2_MAXIDLE - pos,
                                  ", %d second%s", isecs,
                                  isecs == 1 ? "" : "s");
                }
                else
                    snprintf (buf, ENTRY2_MAXIDLE, "%d second%s",
                              isecs, isecs == 1 ? "" : "s");
            }
            else
                buf[0] = '\0';
        }
        strcpy (ent2->istring, buf);
        return 0;               /* success */
    }

    else
        return -1;
}

void
free_entry (entry_t * ent)
{
    if (!ent)
        return;

    if (ent->timep)
        free (ent->timep);
    free (ent);
}

void
free_entry2 (entry2_t * ent)
{
    if (!ent)
        return;

    if (ent->base)
        free (ent->base);
    free (ent);
}

userinfo_t *
match_uid_in_list (userinfo_t * ui, uid_t uid)
{
    userinfo_t *rover;

    for (rover = ui; rover; rover = rover->next)
    {

        if (rover->uid == uid)
            return rover;
    }

    return (userinfo_t *) NULL;

}

#ifdef STANDALONE

#error Fix cprintf

int
main (int argc, char **argv)
{

    list_logins ();

    return 0;
}

#endif /* STANDALONE */
