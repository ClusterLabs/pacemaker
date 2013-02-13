#include <crm_internal.h>
#include <string.h>
/*
 * Copyright (C) 2003 Alan Robertson <alanr@unix.sh>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

size_t
strnlen(const char *s, size_t maxlen)
{
    const char *eospos;

    eospos = memchr(s, (int)'\0', maxlen);

    return (eospos == NULL ? maxlen : (size_t) (eospos - s));
}
