#ifndef __BDFINGER_H_
#define __BDFINGER_H_

#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <utmp.h>


#include "config.h"
#ifndef LINUX
#error Only Linux is working for now, sorry.
#endif

/* #define's go here */

#define BDFINGER_VERSION	"0.9.5"

#define MAX_USERNAME		32

#define DEFAULT_CONF_1		"/usr/local/etc/bdfingerd.conf"
#define DEFAULT_CONF_2		"/etc/bdfingerd.conf"
#define DEFAULT_CONF_3		"/usr/etc/bdfingerd.conf"
#define DEFAULT_CONF_4		"./bdfingerd.conf"

#define CONF_BUF_MAX    1024

#define CVAR_NAME_MAX   64
#define CVAR_STRING_MAX  192   


/* ANSI color escape codes */

#define  ANSI_GREEN             "\x1b[01;32m"
#define  ANSI_BLUE              "\x1b[01;34m"
#define  ANSI_YELLOW            "\x1b[01;33m"
#define  ANSI_RED               "\x1b[01;31m"
#define  ANSI_MAGENTA           "\x1b[01;35m"
#define  ANSI_CYAN              "\x1b[01;36m"
#define  ANSI_WHITE             "\x1b[01;37m"
#define  ANSI_GREY              "\x1b[01;30m"

#define  ANSI_DARKGREEN         "\x1b[00;32m"
#define  ANSI_DARKBLUE          "\x1b[00;34m"
#define  ANSI_BROWN             "\x1b[00;33m"
#define  ANSI_DARKRED           "\x1b[00;31m"
#define  ANSI_PURPLE            "\x1b[00;35m"
#define  ANSI_DARKCYAN          "\x1b[00;36m"
#define  ANSI_BLACK             "\x1b[00;30m"

#define  ANSI_NORMAL            "\x1b[0m"

#define  ANSI_CLRSCRN           "\x1b[2J"
#define  ANSI_CLRLN             "\x1b[K"
#define  ANSI_PUSHCUR           "\x1b[s"
#define  ANSI_POPCUR            "\x1b[u"

#define ONEDAY          (double) (60 * 60 * 24)
#define ONEWEEK         (double) (60 * 60 * 24 * 7)
#define ONEMONTH        (double) (60 * 60 * 60 * 30)
#define SIXMONTHS       (double) (60 * 60 * 24 * 183)   /* more or less... */

#define ENTRY_MAXTSTRING        12
#define ENTRY_MAXNAME           12
#define ENTRY_MAXTTY            8
#define ENTRY_MAXADDR           27
#define ENTRY_MAXISTRING        7
#define ENTRY_MAXRNAME          18

#define ENTRY2_MAXTIME		29	/*  strlen("Tue 10 Apr 2001 13:45 (BRZST)")  */
#define ENTRY2_MAXIDLE		24

#define MAXCLIENTNAME		24
#define MAXLASTLOGIN		32 + UT_LINESIZE + UT_HOSTSIZE
#define SHORTLASTLOGIN		13

#define EURO_DATE_FORMAT1	"%a %e %b %H:%M (%Z)"
#define EURO_DATE_FORMAT2	"%a %e %b %Y %H:%M (%Z)"

#define AMER_DATE_FORMAT1	"%a %b %e %H:%M (%Z)"
#define AMER_DATE_FORMAT2	"%a %b %e %Y %H:%M (%Z)"


#ifdef LINUX
  #define _GNU_SOURCE		/* is this the legit way of doing things? */
#endif

/* typedefs, struct's, etc */

typedef struct userinfo_s
{
        char name[32];
        unsigned short uid, gid;
        char realname[128];
	char office[32];
	char officephone[32];
	char homephone[32];
        char homedir[256];
        char shell[64];
	char lastlogin[MAXLASTLOGIN];
	char lastlogin_short[SHORTLASTLOGIN];
 
        struct userinfo_s *next;
} userinfo_t;


/* entry_t: this one is used by list_logins() to create a
   uniformly white-spaced table of currently
   logged in users */
typedef struct entry_s
{
	struct tm	*timep;
        char            tstring[ENTRY_MAXTSTRING+1];
        char            istring[ENTRY_MAXISTRING+1];
        char               name[ENTRY_MAXNAME + 1];
        char              rname[ENTRY_MAXRNAME+1];
        char                tty[ENTRY_MAXTTY+1];
        char               addr[ENTRY_MAXADDR+1];
	int		msg;
	
	struct entry_s *next;
} entry_t;

/* entry2_t: this is used by get_logins() to store the
   information for a particular user without whitespace
   or size constraints */
typedef struct entry2_s
{
	char		*base; /* malloc() anchors here */
        struct tm       *timep;
        char            *name;
        char            *tty;
        char            *addr;
	time_t		clogin;
        char            tstring[ENTRY2_MAXTIME];
        char            istring[ENTRY2_MAXIDLE];
	int		msg;

        struct entry2_s  *next;
} entry2_t;

typedef struct cvar_s
{       
        char name[CVAR_NAME_MAX]; 
        char string[CVAR_STRING_MAX];
	int	value;
	struct cvar_s *next;
} cvar_t;

/* external variables go here */

extern const	char *COMPILE_DATE;

extern fd_set  active_fd_set, read_fd_set;
extern int     bdfinger_socket;
extern int	i_am_a_child;
extern int	current_children;
extern int	inetd;

extern cvar_t	*cvar_head;

extern cvar_t  *repository, *tty, *pidfile, *maxchildren, *port, *safeuser,
        *timeout, *welcome, *uptime, *allowempty, *multistyle,
	*logging, *showroot, *eurodates, *matchrealnames, *forwarding, *filesizelimit,
        *ignorenofinger, *showmail, *showforward, *showproject, *showplan, *showpgpkey, 
        *showhome, *showshell, *showmisc, *showlogins, *showlastlogin, *showaddr, *showidle;



extern char    child_client[MAXCLIENTNAME];
extern struct userinfo_s 	*userinfo;

/* function prototypes here */

#ifdef DEBUG
 #define dprintf cprintf
#else
 int dprintf (int, const char *, ...);
#endif

void realise_cvars (void);

void catch_sigterm (int);
void catch_sigchld (int);
void catch_sighup (int);

void do_child (int sock);
int cputs (int fd, char *s);
int cputc (int fd, char c);
int cprintf (int fd, const char *fmt, ... );
void child_read_input (char *);
void child_catch_sigalrm (int);
void child_exit (int);

char *banner_string (int upt);
char *uptime_string (void);
char *clock_string (void);
char *time_string (time_t);

int print_special_file (int fd, struct userinfo_s *, char *, char *);
int check_nofinger (struct userinfo_s *);

/* in paragraph.c */
void print_lines_head (int sock);
void print_user_paragraph (int, userinfo_t *);

/* in lines.c */
void print_user_lines (int, userinfo_t *);

char *login_time_string (struct tm *, int which);

int 	stat_tty (void *, int);

struct stat *stat_mailbox (char *);

void list_logins (int sock);
entry2_t *get_logins (char *name);
int get_lastlogin (struct userinfo_s *user, entry2_t *logins);

void do_net_init (int port);
void catch_sigterm (int sig);
void parse_args (int argc, char **argv);
void free_entry (entry_t *ent);

int clog (int pri, char *buf, ...);

int make_socket (uint16_t port);
int do_net_check (int sock);

struct userinfo_s *search_passwd_file (void);
struct userinfo_s *match_passwd_entry (char *);


int	cvar_init (void);
void	destroy_cvars (void);
cvar_t *cvar_find (char *name);
cvar_t *cvar_set (cvar_t *var, char *string);
cvar_t *cvar_set_value (cvar_t *var, int value);

int parse_conf_file (char *);

#endif /* __BDFINGER_H_ */

