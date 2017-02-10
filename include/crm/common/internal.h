/*
 * Copyright (C) 2015
 *     Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef PCMKPRIV_CRMCOMMON_INTERNAL__H
#define   PCMKPRIV_CRMCOMMON_INTERNAL__H

/*!
 * \file
 * \brief   internal common utilities
 * \ingroup core
 * \note    Public APIs are declared in util.h
 */

#include <glib.h>       /* for gboolean */
#include <dirent.h>     /* for struct dirent */
#include <sys/types.h>  /* for uid_t and gid_t */

#include <crm/common/logging.h>

/* internal I/O utilities (from io.c) */

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


/* internal procfs utilities (from procfs.c) */

int crm_procfs_process_info(struct dirent *entry, char *name, int *pid);
int crm_procfs_pid_of(const char *name);


/* internal XML schema functions (from xml.c) */

void crm_schema_init(void);
void crm_schema_cleanup(void);


/* internal generic string functions (from strings.c) */

char *crm_concat(const char *prefix, const char *suffix, char join);
void g_hash_destroy_str(gpointer data);
long long crm_int_helper(const char *text, char **end_text);
gboolean crm_ends_with(const char *s, const char *match);
char *add_list_element(char *list, const char *value);
bool crm_compress_string(const char *data, int length, int max, char **result,
                         unsigned int *result_len);

static inline int
crm_strlen_zero(const char *s)
{
    return !s || *s == '\0';
}

/* convenience functions for failure-related node attributes */

#define CRM_FAIL_COUNT_PREFIX   "fail-count"
#define CRM_LAST_FAILURE_PREFIX "last-failure"

/*!
 * \internal
 * \brief Generate a failure-related node attribute name for a resource
 *
 * \param[in] prefix    Start of attribute name
 * \param[in] rsc_id    Resource name
 *
 * \return Newly allocated string with attribute name
 */
static inline char *
crm_fail_attr_name(const char *prefix, const char *rsc_id)
{
    CRM_CHECK(prefix && rsc_id, return NULL);
    return crm_strdup_printf("%s-%s", prefix, rsc_id);
}

static inline char *
crm_failcount_name(const char *rsc_id)
{
    return crm_fail_attr_name(CRM_FAIL_COUNT_PREFIX, rsc_id);
}

static inline char *
crm_lastfailure_name(const char *rsc_id)
{
    return crm_fail_attr_name(CRM_LAST_FAILURE_PREFIX, rsc_id);
}

#endif  /* PCMKPRIV_CRMCOMMON_INTERNAL__H */
