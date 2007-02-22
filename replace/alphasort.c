/*
 *
 * alphasort - replacement for alphasort functions.
 * 
 * Matt Soffen

 * Copyright (C) 2001 Matt Soffen <matt@soffen.com>
 *
 * Taken from the FreeBSD file (with copyright notice)
 *	/usr/src/gnu/lib/libdialog/dir.c 
 ***************************************************************************
 *	Program:	dir.c
 *	Author:		Marc van Kempen
 *	desc:		Directory routines, sorting and reading
 *
 * Copyright (c) 1995, Marc van Kempen
 *
 * All rights reserved.
 *
 * This software may be used, modified, copied, distributed, and
 * sold, in both source and binary form provided that the above
 * copyright and these terms are retained, verbatim, as the first
 * lines of this file.  Under no circumstances is the author
 * responsible for the proper functioning of this software, nor does
 * the author assume any responsibility for damages incurred with
 * its use.
 *
 ***************************************************************************
 */

#include <lha_internal.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>		/* XXX for _POSIX_VERSION ifdefs */

#if HAVE_STRINGS_H
#include <strings.h>
#endif

#if !defined sgi && !defined _POSIX_VERSION
#include <sys/dir.h>
#endif

#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <stddef.h>

int alphasort(const void *dirent1, const void *dirent2) {
  return(strcmp((*(const struct dirent **)dirent1)->d_name,
                (*(const struct dirent **)dirent2)->d_name));
}
