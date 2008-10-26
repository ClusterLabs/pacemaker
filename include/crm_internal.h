/* crm_internal.h */

/* 
 * Copyright (C) 2006 - 2008
 *     Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef CRM_INTERNAL__H
#define CRM_INTERNAL__H

#include <hb_config.h>
#include <config.h>
#include <portability.h>

/* Prototypes for libreplace functions */

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif

#ifndef HAVE_SETENV
int setenv(const char *name, const char * value, int overwrite);
#endif

#ifndef HAVE_UNSETENV
int unsetenv(const char *name);
#endif

#ifndef HAVE_STRERROR
char * strerror(int errnum);
#endif

#ifndef HAVE_SCANDIR
#  include <dirent.h>
int scandir (const char *dir_name, struct dirent ***array,
	     int (*select_fn) (const struct dirent *),
	     int (*compare_fn) (const void *, const void *));
#endif

#ifndef HAVE_ALPHASORT
#  include <dirent.h>
int alphasort(const void *dirent1, const void *dirent2);
#endif

#ifndef HAVE_INET_PTON
int inet_pton(int af, const char *src, void *dst);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const char *s, size_t maxlen);
#endif

#ifndef HAVE_STRNDUP
char *strndup(const char *str, size_t len);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char * dest, const char *source, size_t len);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char * dest, const char *source, size_t len);
#endif

/*
 * Some compilers do not define __FUNCTION__
 */
/* Sun studio compiler */
# ifdef __SUNPRO_C
#  define __FUNCTION__ __func__
# endif

# ifdef __MY_UNKNOWN_C
#  define __FUNCTION__ "__FUNCTION__"
# endif

#endif /* CRM_INTERNAL__H */
