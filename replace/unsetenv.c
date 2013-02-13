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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <crm_internal.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define __environ       environ
#ifndef HAVE_ENVIRON_DECL
extern char **environ;
#endif

int
unsetenv(const char *name)
{
    const size_t len = strlen(name);
    char **ep;

    for (ep = __environ; *ep; ++ep) {
        if (!strncmp(*ep, name, len) && (*ep)[len] == '=') {
            /* Found it.  */
            /* Remove this pointer by moving later ones back.  */
            char **dp = ep;

            do
                dp[0] = dp[1];
            while (*dp++);
            /* Continue the loop in case NAME appears again.  */
        }
    }
    return 0;
}
