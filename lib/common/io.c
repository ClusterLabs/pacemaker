/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#include <crm/crm.h>
#include <crm/common/util.h>

void
crm_build_path(const char *path_c, mode_t mode)
{
    int offset = 1, len = 0;
    char *path = strdup(path_c);

    CRM_CHECK(path != NULL, return);
    for (len = strlen(path); offset < len; offset++) {
        if (path[offset] == '/') {
            path[offset] = 0;
            if (mkdir(path, mode) < 0 && errno != EEXIST) {
                crm_perror(LOG_ERR, "Could not create directory '%s'", path);
                break;
            }
            path[offset] = '/';
        }
    }
    if (mkdir(path, mode) < 0 && errno != EEXIST) {
        crm_perror(LOG_ERR, "Could not create directory '%s'", path);
    }

    free(path);
}

char *
generate_series_filename(const char *directory, const char *series, int sequence, gboolean bzip)
{
    int len = 40;
    char *filename = NULL;
    const char *ext = "raw";

    CRM_CHECK(directory != NULL, return NULL);
    CRM_CHECK(series != NULL, return NULL);

#if !HAVE_BZLIB_H
    bzip = FALSE;
#endif

    len += strlen(directory);
    len += strlen(series);
    filename = malloc(len);
    CRM_CHECK(filename != NULL, return NULL);

    if (bzip) {
        ext = "bz2";
    }
    sprintf(filename, "%s/%s-%d.%s", directory, series, sequence, ext);

    return filename;
}

int
get_last_sequence(const char *directory, const char *series)
{
    FILE *file_strm = NULL;
    int start = 0, length = 0, read_len = 0;
    char *series_file = NULL;
    char *buffer = NULL;
    int seq = 0;
    int len = 36;

    CRM_CHECK(directory != NULL, return 0);
    CRM_CHECK(series != NULL, return 0);

    len += strlen(directory);
    len += strlen(series);
    series_file = malloc(len);
    CRM_CHECK(series_file != NULL, return 0);
    sprintf(series_file, "%s/%s.last", directory, series);

    file_strm = fopen(series_file, "r");
    if (file_strm == NULL) {
        crm_debug("Series file %s does not exist", series_file);
        free(series_file);
        return 0;
    }

    /* see how big the file is */
    start = ftell(file_strm);
    fseek(file_strm, 0L, SEEK_END);
    length = ftell(file_strm);
    fseek(file_strm, 0L, start);

    CRM_ASSERT(length >= 0);
    CRM_ASSERT(start == ftell(file_strm));

    if (length <= 0) {
        crm_info("%s was not valid", series_file);
        free(buffer);
        buffer = NULL;

    } else {
        crm_trace("Reading %d bytes from file", length);
        buffer = calloc(1, (length + 1));
        read_len = fread(buffer, 1, length, file_strm);
        if (read_len != length) {
            crm_err("Calculated and read bytes differ: %d vs. %d", length, read_len);
            free(buffer);
            buffer = NULL;
        }
    }

    seq = crm_parse_int(buffer, "0");
    fclose(file_strm);

    crm_trace("Found %d in %s", seq, series_file);

    free(series_file);
    free(buffer);
    return seq;
}

void
write_last_sequence(const char *directory, const char *series, int sequence, int max)
{
    int rc = 0;
    int len = 36;
    FILE *file_strm = NULL;
    char *series_file = NULL;

    CRM_CHECK(directory != NULL, return);
    CRM_CHECK(series != NULL, return);

    if (max == 0) {
        return;
    }
    if (max > 0 && sequence >= max) {
        sequence = 0;
    }

    len += strlen(directory);
    len += strlen(series);
    series_file = malloc(len);

    if(series_file) {
        sprintf(series_file, "%s/%s.last", directory, series);
        file_strm = fopen(series_file, "w");
    }

    if (file_strm != NULL) {
        rc = fprintf(file_strm, "%d", sequence);
        if (rc < 0) {
            crm_perror(LOG_ERR, "Cannot write to series file %s", series_file);
        }

    } else {
        crm_err("Cannot open series file %s for writing", series_file);
    }

    if (file_strm != NULL) {
        fflush(file_strm);
        fclose(file_strm);
    }

    crm_trace("Wrote %d to %s", sequence, series_file);
    free(series_file);
}

gboolean
crm_is_writable(const char *dir, const char *file,
                const char *user, const char *group, gboolean need_both)
{
    int s_res = -1;
    struct stat buf;
    char *full_file = NULL;
    const char *target = NULL;

    gboolean pass = TRUE;
    gboolean readwritable = FALSE;

    CRM_ASSERT(dir != NULL);
    if (file != NULL) {
        full_file = crm_concat(dir, file, '/');
        target = full_file;
        s_res = stat(full_file, &buf);
        if (s_res == 0 && S_ISREG(buf.st_mode) == FALSE) {
            crm_err("%s must be a regular file", target);
            pass = FALSE;
            goto out;
        }
    }

    if (s_res != 0) {
        target = dir;
        s_res = stat(dir, &buf);
        if (s_res != 0) {
            crm_err("%s must exist and be a directory", dir);
            pass = FALSE;
            goto out;

        } else if (S_ISDIR(buf.st_mode) == FALSE) {
            crm_err("%s must be a directory", dir);
            pass = FALSE;
        }
    }

    if (user) {
        struct passwd *sys_user = NULL;

        sys_user = getpwnam(user);
        readwritable = (sys_user != NULL
                        && buf.st_uid == sys_user->pw_uid && (buf.st_mode & (S_IRUSR | S_IWUSR)));
        if (readwritable == FALSE) {
            crm_err("%s must be owned and r/w by user %s", target, user);
            if (need_both) {
                pass = FALSE;
            }
        }
    }

    if (group) {
        struct group *sys_grp = getgrnam(group);

        readwritable = (sys_grp != NULL
                        && buf.st_gid == sys_grp->gr_gid && (buf.st_mode & (S_IRGRP | S_IWGRP)));
        if (readwritable == FALSE) {
            if (need_both || user == NULL) {
                pass = FALSE;
                crm_err("%s must be owned and r/w by group %s", target, group);
            } else {
                crm_warn("%s should be owned and r/w by group %s", target, group);
            }
        }
    }

  out:
    free(full_file);
    return pass;
}
