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

/* sock.c for bdfinger */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "bdfinger.h"

char child_client[MAXCLIENTNAME];



/* do_net_init()    This function calls make_socket and begins to listen() */

void
do_net_init (int portnum)
{
    int sock;
    size_t size;

    if (portnum < 1 || portnum > 65535)
    {
        fprintf (stderr, "Bind port %d? I don't think that's doable.\n",
                 portnum);
        exit (EXIT_FAILURE);
    }

    /* Create the socket and set it up to accept connections. */
    sock = make_socket (portnum);
    if (listen (sock, 1) < 0)
    {
        perror ("listen");
        exit (EXIT_FAILURE);
    }

    /* Initialize the set of active sockets. */
    FD_ZERO (&active_fd_set);
    FD_SET (sock, &active_fd_set);

    bdfinger_socket = sock;
}



/* make_socket()  Simple function to create a socket in the internet namespace and
      assign it the appropriate port */

int
make_socket (uint16_t portnum)
{
    int sock;
    struct sockaddr_in name;

    /* Create the socket. */
    sock = socket (PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror ("socket");
        exit (EXIT_FAILURE);
    }

    /* Give the socket a name. */
    name.sin_family = AF_INET;
    name.sin_port = htons (portnum);
    name.sin_addr.s_addr = htonl (INADDR_ANY);
    if (bind (sock, (struct sockaddr *) &name, sizeof (name)) < 0)
    {
        perror ("bind");
        exit (EXIT_FAILURE);
    }

    return sock;
}



/* do_net_check() is called repetitively by main() to check for new connections on the 
     socket */

int
do_net_check (int sock)
{
    int i;
    struct sockaddr_in clientname;
    size_t size;
    struct timeval tv;
    pid_t p;


    tv.tv_sec = 0;
    tv.tv_usec = 0;

    /* Block until input arrives on one or more active sockets. */
    read_fd_set = active_fd_set;

    if (select (FD_SETSIZE, &read_fd_set, NULL, NULL, &tv) < 0)
    {
        perror ("select");
        exit (EXIT_FAILURE);
    }

    /* Service all the sockets with input pending. */
    for (i = 0; i < FD_SETSIZE; ++i)
        if (FD_ISSET (i, &read_fd_set))
        {
            if (i == sock)
            {
                /* Connection request on original socket. */
                int new;
                size = sizeof (clientname);
                new = accept (sock, (struct sockaddr *) &clientname, &size);
                if (new < 0)
                {
                    perror ("accept");
                    exit (EXIT_FAILURE);
                }
                fprintf (stderr,
                         "Server: connect from host %s, port %hd.\n",
                         inet_ntoa (clientname.sin_addr),
                         ntohs (clientname.sin_port));

                p = fork ();
                switch (p)
                {
                case -1:
                    perror ("fork");
                    close (new);
                    break;
                case 0:
                    i_am_a_child = 1;
                    strncpy (child_client, inet_ntoa (clientname.sin_addr),
                             MAXCLIENTNAME);
                    do_child (new);
                    fprintf (stderr, "warning! do_child() returned!\n");
                    /* this should never happen */
                    break;
                default:
                    fprintf (stderr, "child (%u) forked\n", p);
                    current_children++;
                    break;
                }
                close (new);
            }
            else
            {
                fprintf (stderr, "lingering client ?\n");
            }
        }
}



/* init_sockaddr()   is only used by the finger forwarding code, when creating a new 
         socket to a third party host */

void
init_sockaddr (struct sockaddr_in *name, const char *hostname, uint16_t port)
{
    struct hostent *hostinfo;

    name->sin_family = AF_INET;
    name->sin_port = htons (port);
    hostinfo = gethostbyname (hostname);
    if (hostinfo == NULL)
    {
        fprintf (stderr, "Unknown host %s.\n", hostname);
        exit (EXIT_FAILURE);
    }
    name->sin_addr = *(struct in_addr *) hostinfo->h_addr;
}
