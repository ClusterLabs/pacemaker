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
 * \brief internal I/O utilities
 * \ingroup core
 */

/* public APIs from io.c are declared in util.h */

#ifndef CRM_COMMON_IO__H
#define CRM_COMMON_IO__H

#include <glib.h> /* for gboolean */

char *generate_series_filename(const char *directory, const char *series, int sequence,
                               gboolean bzip);
int get_last_sequence(const char *directory, const char *series);
void write_last_sequence(const char *directory, const char *series, int sequence, int max);
int crm_chown_last_sequence(const char *directory, const char *series, uid_t uid, gid_t gid);

gboolean crm_is_writable(const char *dir, const char *file, const char *user, const char *group,
                         gboolean need_both);

void crm_sync_directory(const char *name);

char *crm_read_contents(const char *filename);
int crm_write_sync(int fd, const char *contents);

#endif /* CRM_COMMON_IO__H */
