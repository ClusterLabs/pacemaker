#ifndef PORTABILITY_H
#  define PORTABILITY_H

/*
 * Copyright (C) 2001 Alan Robertson <alanr@unix.sh>
 * This software licensed under the GNU LGPL.
 *
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#  define	EOS			'\0'
#  define	DIMOF(a)		((int) (sizeof(a)/sizeof(a[0])) )

/* Needs to be defined before any other includes, otherwise some system
 * headers do not behave as expected! Major black magic... */
#  undef _GNU_SOURCE            /* in case it was defined on the command line */
#  define _GNU_SOURCE

/* Please leave this as the first #include - Solaris needs it there */
#  ifdef HAVE_CONFIG_H
#    include <config.h>
#  endif

/* Prototypes for libreplace functions */

#  ifndef HAVE_DAEMON
  /* We supply a replacement function, but need a prototype */
int daemon(int nochdir, int noclose);
#  endif                        /* HAVE_DAEMON */

#  ifndef HAVE_SETENV
  /* We supply a replacement function, but need a prototype */
int setenv(const char *name, const char *value, int why);
#  endif                        /* HAVE_SETENV */

#  ifndef HAVE_STRERROR
  /* We supply a replacement function, but need a prototype */
char *strerror(int errnum);
#  endif                        /* HAVE_STRERROR */

#  ifndef HAVE_ALPHASORT
#    include <dirent.h>
int
 alphasort(const void *dirent1, const void *dirent2);
#  endif                        /* HAVE_ALPHASORT */

#  ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen);
#  else
#    	define USE_GNU
#  endif

#  ifndef HAVE_STRNDUP
char *strndup(const char *str, size_t len);
#  else
#    	define USE_GNU
#  endif

/*
 * Some compilers (eg. Sun studio) do not define __FUNCTION__
 */
#  ifdef __SUNPRO_C
#    define __FUNCTION__ __func__
#  endif

#  ifdef __MY_UNKNOWN_C
#    define __FUNCTION__ "__FUNCTION__"
#  endif

#endif                          /* PORTABILITY_H */
