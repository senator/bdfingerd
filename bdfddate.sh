#!/bin/sh

cat << EOF > bdfddate.c

/* bdfddate.c */
/* built by bdfddate.sh, this file defines the extern COMPILE_DATE
   as the date/time at which the application was last built. */

const char *COMPILE_DATE = "`date`";

/* end bdfddate.c */

EOF

