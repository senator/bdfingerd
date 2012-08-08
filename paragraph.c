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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "bdfinger.h"


void
print_user_paragraph (int sock, userinfo_t * u)
{
    entry2_t *logins, *lp, *oldlp;
    userinfo_t *oldu;
    int sl;
    int i;
    struct stat *sb;
    char *mailgot, *mailread, *mailmade;
    int mailforwarded = 0;



    /* FIXME: u->name might be truncated and so wouldn't always work.
       Use a hash ? */


    logins = get_logins (u->name);
    sl = get_lastlogin (u, logins);

    /* To be RFC 1288 compliant, the finger daemon must always at least
       display the full name of the queried user */
    cprintf (sock, "Login: %-27s  Real Name: %-30s\n", u->name, u->realname);

    if (showhome->value)
        cprintf (sock, "Home Dir: %-24s      ", u->homedir);
    if (showshell->value)
        cprintf (sock, "Shell: %-30s\n", u->shell);
    else if (showhome->value)
        cprintf (sock, "\n");

    if (showmisc->value)
    {
        if (strlen (u->office) > 0)
            cprintf (sock, "Office: %s\n", u->office);
        if (strlen (u->officephone) > 0)
            cprintf (sock, "Office Ph: %s\n", u->officephone);
        if (strlen (u->homephone) > 0)
            cprintf (sock, "Home Ph: %s\n", u->homephone);
    }

    if (logins && showlogins->value)
    {
        lp = logins;
        while (lp)
        {
            cprintf (sock, "On since %s on %s", lp->tstring, lp->tty);
            if (lp->msg == 0)
                cprintf (sock, " (msgs off)");
            if (strlen (lp->addr) > 0 && showaddr->value)
            {
                if (strlen (lp->addr) > 24 || !lp->msg)
                    cprintf (sock, "\n  from %s", lp->addr);
                else
                    cprintf (sock, " from %s", lp->addr);
            }
            if (strlen (lp->istring) > 0 && showidle->value)
            {
                if ((strlen (lp->addr) > 0 && showaddr->value) || !lp->msg)
                    cprintf (sock, "\n    %s idle", lp->istring);
                else
                    cprintf (sock, "%-*s%s idle",
                             ENTRY_MAXTTY - strlen (lp->tty) + 1, " ",
                             lp->istring);
            }
            cprintf (sock, "\n");
            oldlp = lp;
            lp = lp->next;
            free_entry2 (oldlp);
        }
    }

    if (sl == 0 && showlastlogin->value)
    {
        if (strlen (u->lastlogin) > 0)
            cprintf (sock, "Last login %s\n", u->lastlogin);
        else
            cprintf (sock, "Never logged in.\n");
    }


    if (showforward->value)
        mailforwarded =
            !print_special_file (sock, u, "forward", "Mail forwarded to ");

    if (showmail->value)
        if (!mailforwarded)
        {
            sb = stat_mailbox (u->name);
            if (sb)
            {
                mailgot = time_string (sb->st_mtime);
                mailread = time_string (sb->st_atime);

                if (sb->st_size == 0)
                    cprintf (sock, "No mail.\n");
                else
                {

                    if (sb->st_mtime > sb->st_atime)
                    {
                        cprintf (sock, "New mail arrived %s\n", mailgot);
                        cprintf (sock, "    Unread since %s\n",
                                 sb->st_atime ==
                                 (time_t) 0 ? "the epoch." : mailread);
                    }
                    else
                        cprintf (sock, "Mail last read %s\n", mailread);
                }

                if (mailgot)
                    free (mailgot);
                if (mailread)
                    free (mailread);
            }

            else
                cprintf (sock, "No mail.\n");
        }

    if (showproject->value)
        print_special_file (sock, u, "project", "Project: ");
    if (showplan->value)
        if (print_special_file (sock, u, "plan", "Plan:\n") != 0)
            cprintf (sock, "No plan.\n");
    if (showpgpkey->value)
        print_special_file (sock, u, "pgpkey", "PGP Key:\n");

}

/* end paragraph.c */
