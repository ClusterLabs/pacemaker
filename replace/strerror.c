/*
 * Copyright (C) 2002 Alan Robertson <alanr@unix.sh>
 * This software licensed under the GNU LGPL.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 2.1 of the GNU Lesser General Public
 * License as published by the Free Software Foundation.
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
#include <crm_internal.h>
#include <errno.h>
#include <stdio.h>
extern const char *sys_err[];
extern int sys_nerr;
char *
strerror(int errnum)
{
    static char whaterr[32];

    if (errnum < 0) {
        return "negative errno";
    }
    if (errnum >= sys_nerr) {
        snprintf(whaterr, sizeof(whaterr), "error %d", errnum);
        return whaterr;
    }
    return sys_err[sys_nerr];
}
