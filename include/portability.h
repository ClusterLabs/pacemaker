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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA *
 */

#define	EOS			'\0'
#define	DIMOF(a)		((int) (sizeof(a)/sizeof(a[0])) )
#define	STRLEN_CONST(conststr)  ((size_t)((sizeof(conststr)/sizeof(char))-1))
#define	STRNCMP_CONST(varstr, conststr) strncmp((varstr), conststr, STRLEN_CONST(conststr)+1)
#define	STRLEN(c)		STRLEN_CONST(c)

/* Needs to be defined before any other includes, otherwise some system
 * headers do not behave as expected! Major black magic... */
#undef _GNU_SOURCE  /* in case it was defined on the command line */
#define _GNU_SOURCE

/* Please leave this as the first #include - Solaris needs it there */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/param.h>
#ifdef BSD
#	define SCANSEL_CAST	(void *)
#else
#	define SCANSEL_CAST	/* Nothing */
#endif

#if defined(ANSI_ONLY) && !defined(inline)
#	define inline	/* nothing */
#	undef	NETSNMP_ENABLE_INLINE
#	define	NETSNMP_NO_INLINE 1
#endif

#ifndef HA_HAVE_DAEMON
  /* We supply a replacement function, but need a prototype */
int daemon(int nochdir, int noclose);
#endif /* HA_HAVE_DAEMON */

#ifndef HA_HAVE_SETENV
  /* We supply a replacement function, but need a prototype */
int setenv(const char *name, const char * value, int why);
#endif /* HA_HAVE_SETENV */

#ifndef HA_HAVE_STRERROR
  /* We supply a replacement function, but need a prototype */
char * strerror(int errnum);
#endif /* HA_HAVE_STRERROR */

#ifndef HA_HAVE_ALPHASORT
#  include <dirent.h>
int
alphasort(const void *dirent1, const void *dirent2);
#endif /* HA_HAVE_ALPHASORT */

#ifndef HA_HAVE_INET_PTON
  /* We supply a replacement function, but need a prototype */
int
inet_pton(int af, const char *src, void *dst);

#endif /* HA_HAVE_INET_PTON */

#ifndef HA_HAVE_STRNLEN
	size_t strnlen(const char *s, size_t maxlen);
#else
#	define USE_GNU
#endif

#ifndef HA_HAVE_STRNDUP
	char *strndup(const char *str, size_t len);
#else
#	define USE_GNU
#endif

#ifndef HA_HAVE_NFDS_T 
	typedef unsigned int nfds_t;
#endif

#ifdef HAVE_STRUCT_UCRED_DARWIN
#	include <sys/utsname.h>
#	ifndef SYS_NMLN
#		define SYS_NMLN _SYS_NAMELEN
#	endif /* SYS_NMLN */
#endif

#define	POINTER_TO_SIZE_T(p)	((size_t)(p)) /*pointer cast as size_t*/
#define	POINTER_TO_SSIZE_T(p)	((ssize_t)(p)) /*pointer cast as ssize_t*/
#define	POINTER_TO_ULONG(p)	((unsigned long)(p)) /*pointer cast as unsigned long*/

#define	HAURL(url)	HA_URLBASE url

#endif /* PORTABILITY_H */
