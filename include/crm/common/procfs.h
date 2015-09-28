/*
 * Copyright (C) 2015
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
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * \file
 * \brief internal procfs utilities
 * \ingroup core
 */

/* public APIs from procfs.c are declared in util.h */

#ifndef CRM_COMMON_PROCFS__H
#define CRM_COMMON_PROCFS__H

#include <sys/types.h>
#include <dirent.h>

int crm_procfs_process_info(struct dirent *entry, char *name, int *pid);
int crm_procfs_pid_of(const char *name);

#endif /* CRM_COMMON_PROCFS__H */
