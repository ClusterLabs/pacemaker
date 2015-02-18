/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <crm_internal.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>

/*!
 * \internal
 * \brief Return canonicalized form of a path name, like realpath(path, NULL)
 *
 * \param[in] path Pathname to canonicalize
 *
 * \return Canonicalized pathname
 * \note The caller is responsible for freeing the result of this funtion.
 */
char *
crm_compat_realpath(const char *path)
{
#if _POSIX_VERSION >= 200809L
    /* Recent C libraries can dynamically allocate memory as needed */
    return realpath(path, NULL);

#elif defined(PATH_MAX)
    /* Older implementations require pre-allocated memory */
    /* (this is less desirable because PATH_MAX may be huge or not defined) */
    char *canonicalized = malloc(PATH_MAX);
    if ((canonicalized == NULL) || (realpath(path, canonicalized) == NULL)) {
        return NULL;
    }
    return canonicalized;
#else
    errno = ENOTSUP;
    return NULL;
#endif
}
