/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
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
#include <fcntl.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>

#include <crm/crm.h>
#include <crm/common/util.h>

/*!
 * \brief Create a directory, including any parent directories needed
 *
 * \param[in] path_c Pathname of the directory to create
 * \param[in] mode Permissions to be used (with current umask) when creating
 *
 * \note This logs errors but does not return them to the caller.
 */
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

/*!
 * \internal
 * \brief Allocate and create a file path using a sequence number
 *
 * \param[in] directory Directory that contains the file series
 * \param[in] series Start of file name
 * \param[in] sequence Sequence number (MUST be less than 33 digits)
 * \param[in] bzip Whether to use ".bz2" instead of ".raw" as extension
 *
 * \return Newly allocated file path, or NULL on error
 * \note Caller is responsible for freeing the returned memory
 */
char *
generate_series_filename(const char *directory, const char *series, int sequence, gboolean bzip)
{
    const char *ext = "raw";

    CRM_CHECK(directory != NULL, return NULL);
    CRM_CHECK(series != NULL, return NULL);

#if !HAVE_BZLIB_H
    bzip = FALSE;
#endif

    if (bzip) {
        ext = "bz2";
    }
    return crm_strdup_printf("%s/%s-%d.%s", directory, series, sequence, ext);
}

/*!
 * \internal
 * \brief Read and return sequence number stored in a file series' .last file
 *
 * \param[in] directory Directory that contains the file series
 * \param[in] series Start of file name
 *
 * \return The last sequence number, or 0 on error
 */
int
get_last_sequence(const char *directory, const char *series)
{
    FILE *file_strm = NULL;
    int start = 0, length = 0, read_len = 0;
    char *series_file = NULL;
    char *buffer = NULL;
    int seq = 0;

    CRM_CHECK(directory != NULL, return 0);
    CRM_CHECK(series != NULL, return 0);

    series_file = crm_strdup_printf("%s/%s.last", directory, series);
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

/*!
 * \internal
 * \brief Write sequence number to a file series' .last file
 *
 * \param[in] directory Directory that contains the file series
 * \param[in] series Start of file name
 * \param[in] sequence Sequence number to write
 * \param[in] max Maximum sequence value, after which sequence is reset to 0
 *
 * \note This function logs some errors but does not return any to the caller
 */
void
write_last_sequence(const char *directory, const char *series, int sequence, int max)
{
    int rc = 0;
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

    series_file = crm_strdup_printf("%s/%s.last", directory, series);
    file_strm = fopen(series_file, "w");
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

/*!
 * \internal
 * \brief Change the owner and group of a file series' .last file
 *
 * \param[in] dir Directory that contains series
 * \param[in] uid Uid of desired file owner
 * \param[in] gid Gid of desired file group
 *
 * \return 0 on success, -1 on error (in which case errno will be set)
 * \note The caller must have the appropriate privileges.
 */
int
crm_chown_last_sequence(const char *directory, const char *series, uid_t uid, gid_t gid)
{
    char *series_file = NULL;
    int rc;

    CRM_CHECK((directory != NULL) && (series != NULL), errno = EINVAL; return -1);

    series_file = crm_strdup_printf("%s/%s.last", directory, series);
    CRM_CHECK(series_file != NULL, return -1);

    rc = chown(series_file, uid, gid);
    free(series_file);
    return rc;
}

static bool
pcmk__daemon_user_can_write(const char *target_name, struct stat *target_stat)
{
    struct passwd *sys_user = NULL;

    errno = 0;
    sys_user = getpwnam(CRM_DAEMON_USER);
    if (sys_user == NULL) {
        crm_notice("Could not find user %s: %s",
                   CRM_DAEMON_USER, pcmk_strerror(errno));
        return FALSE;
    }
    if (target_stat->st_uid != sys_user->pw_uid) {
        crm_notice("%s is not owned by user %s " CRM_XS " uid %d != %d",
                   target_name, CRM_DAEMON_USER, sys_user->pw_uid,
                   target_stat->st_uid);
        return FALSE;
    }
    if ((target_stat->st_mode & (S_IRUSR | S_IWUSR)) == 0) {
        crm_notice("%s is not readable and writable by user %s "
                   CRM_XS " st_mode=0%lo",
                   target_name, CRM_DAEMON_USER,
                   (unsigned long) target_stat->st_mode);
        return FALSE;
    }
    return TRUE;
}

static bool
pcmk__daemon_group_can_write(const char *target_name, struct stat *target_stat)
{
    struct group *sys_grp = NULL;

    errno = 0;
    sys_grp = getgrnam(CRM_DAEMON_GROUP);
    if (sys_grp == NULL) {
        crm_notice("Could not find group %s: %s",
                   CRM_DAEMON_GROUP, pcmk_strerror(errno));
        return FALSE;
    }

    if (target_stat->st_gid != sys_grp->gr_gid) {
        crm_notice("%s is not owned by group %s " CRM_XS " uid %d != %d",
                   target_name, CRM_DAEMON_GROUP,
                   sys_grp->gr_gid, target_stat->st_gid);
        return FALSE;
    }

    if ((target_stat->st_mode & (S_IRGRP | S_IWGRP)) == 0) {
        crm_notice("%s is not readable and writable by group %s "
                   CRM_XS " st_mode=0%lo",
                   target_name, CRM_DAEMON_GROUP,
                   (unsigned long) target_stat->st_mode);
        return FALSE;
    }
    return TRUE;
}

/*!
 * \internal
 * \brief Check whether a directory or file is writable by the cluster daemon
 *
 * Return TRUE if either the cluster daemon user or cluster daemon group has
 * write permission on a specified file or directory.
 *
 * \param[in] dir      Directory to check (this argument must be specified, and
 *                     the directory must exist)
 * \param[in] file     File to check (only the directory will be checked if this
 *                     argument is not specified or the file does not exist)
 *
 * \return TRUE if target is writable by cluster daemon, FALSE otherwise
 */
bool
pcmk__daemon_can_write(const char *dir, const char *file)
{
    int s_res = 0;
    struct stat buf;
    char *full_file = NULL;
    const char *target = NULL;

    // Caller must supply directory
    CRM_ASSERT(dir != NULL);

    // If file is given, check whether it exists as a regular file
    if (file != NULL) {
        full_file = crm_concat(dir, file, '/');
        target = full_file;

        s_res = stat(full_file, &buf);
        if (s_res < 0) {
            crm_notice("%s not found: %s", target, pcmk_strerror(errno));
            free(full_file);
            full_file = NULL;
            target = NULL;

        } else if (S_ISREG(buf.st_mode) == FALSE) {
            crm_err("%s must be a regular file " CRM_XS " st_mode=0%lo",
                    target, (unsigned long) buf.st_mode);
            free(full_file);
            return FALSE;
        }
    }

    // If file is not given, ensure dir exists as directory
    if (target == NULL) {
        target = dir;
        s_res = stat(dir, &buf);
        if (s_res < 0) {
            crm_err("%s not found: %s", dir, pcmk_strerror(errno));
            return FALSE;

        } else if (S_ISDIR(buf.st_mode) == FALSE) {
            crm_err("%s must be a directory " CRM_XS " st_mode=0%lo",
                    dir, (unsigned long) buf.st_mode);
            return FALSE;
        }
    }

    if (!pcmk__daemon_user_can_write(target, &buf)
        && !pcmk__daemon_group_can_write(target, &buf)) {

        crm_err("%s must be owned and writable by either user %s or group %s "
                CRM_XS " st_mode=0%lo",
                target, CRM_DAEMON_USER, CRM_DAEMON_GROUP,
                (unsigned long) buf.st_mode);
        free(full_file);
        return FALSE;
    }

    free(full_file);
    return TRUE;
}

/*!
 * \internal
 * \brief Flush and sync a directory to disk
 *
 * \param[in] name Directory to flush and sync
 * \note This function logs errors but does not return them to the caller
 */
void
crm_sync_directory(const char *name)
{
    int fd;
    DIR *directory;

    directory = opendir(name);
    if (directory == NULL) {
        crm_perror(LOG_ERR, "Could not open %s for syncing", name);
        return;
    }

    fd = dirfd(directory);
    if (fd < 0) {
        crm_perror(LOG_ERR, "Could not obtain file descriptor for %s", name);
        return;
    }

    if (fsync(fd) < 0) {
        crm_perror(LOG_ERR, "Could not sync %s", name);
    }
    if (closedir(directory) < 0) {
        crm_perror(LOG_ERR, "Could not close %s after fsync", name);
    }
}

/*!
 * \internal
 * \brief Allocate, read and return the contents of a file
 *
 * \param[in] filename Name of file to read
 *
 * \return Newly allocated memory with contents of file, or NULL on error
 * \note On success, the caller is responsible for freeing the returned memory;
 *       on error, errno will be 0 (indicating file was nonexistent or empty)
 *       or one of the errno values set by fopen, ftell, or calloc
 */
char *
crm_read_contents(const char *filename)
{
    char *contents = NULL;
    FILE *fp;
    int length, read_len;

    errno = 0; /* enable caller to distinguish error from empty file */

    fp = fopen(filename, "r");
    if (fp == NULL) {
        return NULL;
    }

    fseek(fp, 0L, SEEK_END);
    length = ftell(fp);

    if (length > 0) {
        contents = calloc(length + 1, sizeof(char));
        if (contents == NULL) {
            fclose(fp);
            return NULL;
        }

        crm_trace("Reading %d bytes from %s", length, filename);
        rewind(fp);
        read_len = fread(contents, 1, length, fp);   /* Coverity: False positive */
        if (read_len != length) {
            free(contents);
            contents = NULL;
        }
    }

    fclose(fp);
    return contents;
}

/*!
 * \internal
 * \brief Write text to a file, flush and sync it to disk, then close the file
 *
 * \param[in] fd File descriptor opened for writing
 * \param[in] contents String to write to file
 *
 * \return 0 on success, -1 on error (in which case errno will be set)
 */
int
crm_write_sync(int fd, const char *contents)
{
    int rc = 0;
    FILE *fp = fdopen(fd, "w");

    if (fp == NULL) {
        return -1;
    }
    if ((contents != NULL) && (fprintf(fp, "%s", contents) < 0)) {
        rc = -1;
    }
    if (fflush(fp) != 0) {
        rc = -1;
    }
    if (fsync(fileno(fp)) < 0) {
        rc = -1;
    }
    fclose(fp);
    return rc;
}

/*!
 * \internal
 * \brief Set a file descriptor to non-blocking
 *
 * \param[in] fd  File descriptor to use
 *
 * \return pcmk_ok on success, -errno on error
 */
int
crm_set_nonblocking(int fd)
{
    int flag = fcntl(fd, F_GETFL);

    if (flag < 0) {
        return -errno;
    }
    if (fcntl(fd, F_SETFL, flag | O_NONBLOCK) < 0) {
        return -errno;
    }
    return pcmk_ok;
}

const char *
crm_get_tmpdir()
{
    const char *dir = getenv("TMPDIR");

    return (dir && (*dir == '/'))? dir : "/tmp";
}
