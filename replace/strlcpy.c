#include <crm_internal.h>
#include <string.h>
/*
 * Copyright (C) 2007 Alan Robertson <alanr@unix.sh>
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

size_t
strlcpy(char *dest, const char * src, size_t maxlen)
{
	size_t	srclen = strlen(src);
	if (maxlen > 0) {
		strncpy(dest, src, maxlen);
		dest[maxlen-1]=EOS;
	}
	return srclen;
}
