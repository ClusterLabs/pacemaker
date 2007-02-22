#include <lha_internal.h>
#include <stdlib.h>
#include <string.h>
/*
 * Copyright (C) 2004 Matt Soffen <sirgeek-ha@mrsucko.org>
 * This software licensed under the GNU LGPL.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/* Taken from the GlibC implementation of strndup */

char *strndup(const char *str, size_t len)
{
	size_t n = strnlen(str,len);
	char *new = (char *) malloc (len+1);

	if (NULL == new) {
		return NULL;
	}

	new[n] = '\0';
	return (char *)memcpy (new, str, len);
}

