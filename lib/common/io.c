/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>

#include <crm/crm.h>
#include <crm/common/util.h>

/*!
 * \internal
 * \brief Create a directory, including any parent directories needed
 *
 * \param[in] path_c Pathname of the directory to create
 * \param[in] mode Permissions to be used (with current umask) when creating
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__build_path(const char *path_c, mode_t mode)
{
    int offset = 1, len = 0;
    int rc = pcmk_rc_ok;
    char *path = strdup(path_c);

    CRM_CHECK(path != NULL, return -ENOMEM);
    for (len = strlen(path); offset < len; offset++) {
        if (path[offset] == '/') {
            path[offset] = 0;
            if ((mkdir(path, mode) < 0) && (errno != EEXIST)) {
                rc = errno;
                goto done;
            }
            path[offset] = '/';
        }
    }
    if ((mkdir(path, mode) < 0) && (errno != EEXIST)) {
        rc = errno;
    }
done:
    free(path);
    return rc;
}

/*!
 * \internal
 * \brief Return canonicalized form of a path name
 *
 * \param[in]  path           Pathname to canonicalize
 * \param[out] resolved_path  Where to store canonicalized pathname
 *
 * \return Standard Pacemaker return code
 * \note The caller is responsible for freeing \p resolved_path on success.
 * \note This function exists because not all C library versions of
 *       realpath(path, resolved_path) support a NULL resolved_path.
 */
int
pcmk__real_path(const char *path, char **resolved_path)
{
    CRM_CHECK((path != NULL) && (resolved_path != NULL), return EINVAL);

#if _POSIX_VERSION >= 200809L
    /* Recent C libraries can dynamically allocate memory as needed */
    *resolved_path = realpath(path, NULL);
    return (*resolved_path == NULL)? errno : pcmk_rc_ok;

#elif defined(PATH_MAX)
    /* Older implementations require pre-allocated memory */
    /* (this is less desirable because PATH_MAX may be huge or not defined) */
    *resolved_path = malloc(PATH_MAX);
    if ((*resolved_path == NULL) || (realpath(path, *resolved_path) == NULL)) {
        return errno;
    }
    return pcmk_rc_ok;
#else
    *resolved_path = NULL;
    return ENOTSUP;
#endif
}

/*!
 * \internal
 * \brief Create a file name using a sequence number
 *
 * \param[in] directory  Directory that contains the file series
 * \param[in] series     Start of file name
 * \param[in] sequence   Sequence number
 * \param[in] bzip       Whether to use ".bz2" instead of ".raw" as extension
 *
 * \return Newly allocated file path (asserts on error, so always non-NULL)
 * \note The caller is responsible for freeing the return value.
 */
char *
pcmk__series_filename(const char *directory, const char *series,
                      unsigned int sequence, bool bzip)
{
    pcmk__assert((directory != NULL) && (series != NULL));
    return crm_strdup_printf("%s/%s-%u.%s", directory, series, sequence,
                             (bzip? "bz2" : "raw"));
}

/*!
 * \internal
 * \brief Read sequence number stored in a file series' .last file
 *
 * \param[in]  directory  Directory that contains the file series
 * \param[in]  series     Start of file name
 * \param[out] seq        Where to store the sequence number
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__read_series_sequence(const char *directory, const char *series,
                           unsigned int *seq)
{
    int rc;
    FILE *fp = NULL;
    char *series_file = NULL;

    if ((directory == NULL) || (series == NULL) || (seq == NULL)) {
        return EINVAL;
    }

    series_file = crm_strdup_printf("%s/%s.last", directory, series);
    fp = fopen(series_file, "r");
    if (fp == NULL) {
        rc = errno;
        crm_debug("Could not open series file %s: %s",
                  series_file, strerror(rc));
        free(series_file);
        return rc;
    }
    errno = 0;
    if (fscanf(fp, "%u", seq) != 1) {
        rc = (errno == 0)? ENODATA : errno;
        crm_debug("Could not read sequence number from series file %s: %s",
                  series_file, pcmk_rc_str(rc));
        fclose(fp);
        free(series_file);
        return rc;
    }
    fclose(fp);
    crm_trace("Found last sequence number %u in series file %s",
              *seq, series_file);
    free(series_file);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Write sequence number to a file series' .last file
 *
 * \param[in] directory  Directory that contains the file series
 * \param[in] series     Start of file name
 * \param[in] sequence   Sequence number to write
 * \param[in] max        Maximum sequence value, after which it is reset to 0
 *
 * \note This function logs some errors but does not return any to the caller
 */
void
pcmk__write_series_sequence(const char *directory, const char *series,
                            unsigned int sequence, int max)
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
        rc = fprintf(file_strm, "%u", sequence);
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
 * \param[in] directory  Directory that contains series
 * \param[in] series     Series to change
 * \param[in] uid        User ID of desired file owner
 * \param[in] gid        Group ID of desired file group
 *
 * \return Standard Pacemaker return code
 * \note The caller must have the appropriate privileges.
 */
int
pcmk__chown_series_sequence(const char *directory, const char *series,
                            uid_t uid, gid_t gid)
{
    char *series_file = NULL;
    int rc = pcmk_rc_ok;

    if ((directory == NULL) || (series == NULL)) {
        return EINVAL;
    }
    series_file = crm_strdup_printf("%s/%s.last", directory, series);
    if (chown(series_file, uid, gid) < 0) {
        rc = errno;
    }
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
                   CRM_DAEMON_USER, pcmk_rc_str(errno));
        return FALSE;
    }
    if (target_stat->st_uid != sys_user->pw_uid) {
        crm_notice("%s is not owned by user %s " QB_XS " uid %d != %d",
                   target_name, CRM_DAEMON_USER, sys_user->pw_uid,
                   target_stat->st_uid);
        return FALSE;
    }
    if ((target_stat->st_mode & (S_IRUSR | S_IWUSR)) == 0) {
        crm_notice("%s is not readable and writable by user %s "
                   QB_XS " st_mode=0%lo",
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
                   CRM_DAEMON_GROUP, pcmk_rc_str(errno));
        return FALSE;
    }

    if (target_stat->st_gid != sys_grp->gr_gid) {
        crm_notice("%s is not owned by group %s " QB_XS " uid %d != %d",
                   target_name, CRM_DAEMON_GROUP,
                   sys_grp->gr_gid, target_stat->st_gid);
        return FALSE;
    }

    if ((target_stat->st_mode & (S_IRGRP | S_IWGRP)) == 0) {
        crm_notice("%s is not readable and writable by group %s "
                   QB_XS " st_mode=0%lo",
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
 * Return true if either the cluster daemon user or cluster daemon group has
 * write permission on a specified file or directory.
 *
 * \param[in] dir      Directory to check (this argument must be specified, and
 *                     the directory must exist)
 * \param[in] file     File to check (only the directory will be checked if this
 *                     argument is not specified or the file does not exist)
 *
 * \return true if target is writable by cluster daemon, false otherwise
 */
bool
pcmk__daemon_can_write(const char *dir, const char *file)
{
    int s_res = 0;
    struct stat buf;
    char *full_file = NULL;
    const char *target = NULL;

    // Caller must supply directory
    pcmk__assert(dir != NULL);

    // If file is given, check whether it exists as a regular file
    if (file != NULL) {
        full_file = crm_strdup_printf("%s/%s", dir, file);
        target = full_file;

        s_res = stat(full_file, &buf);
        if (s_res < 0) {
            crm_notice("%s not found: %s", target, pcmk_rc_str(errno));
            free(full_file);
            full_file = NULL;
            target = NULL;

        } else if (S_ISREG(buf.st_mode) == FALSE) {
            crm_err("%s must be a regular file " QB_XS " st_mode=0%lo",
                    target, (unsigned long) buf.st_mode);
            free(full_file);
            return false;
        }
    }

    // If file is not given, ensure dir exists as directory
    if (target == NULL) {
        target = dir;
        s_res = stat(dir, &buf);
        if (s_res < 0) {
            crm_err("%s not found: %s", dir, pcmk_rc_str(errno));
            return false;

        } else if (S_ISDIR(buf.st_mode) == FALSE) {
            crm_err("%s must be a directory " QB_XS " st_mode=0%lo",
                    dir, (unsigned long) buf.st_mode);
            return false;
        }
    }

    if (!pcmk__daemon_user_can_write(target, &buf)
        && !pcmk__daemon_group_can_write(target, &buf)) {

        crm_err("%s must be owned and writable by either user %s or group %s "
                QB_XS " st_mode=0%lo",
                target, CRM_DAEMON_USER, CRM_DAEMON_GROUP,
                (unsigned long) buf.st_mode);
        free(full_file);
        return false;
    }

    free(full_file);
    return true;
}

/*!
 * \internal
 * \brief Flush and sync a directory to disk
 *
 * \param[in] name Directory to flush and sync
 * \note This function logs errors but does not return them to the caller
 */
void
pcmk__sync_directory(const char *name)
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
 * \brief Read the contents of a file
 *
 * \param[in]  filename  Name of file to read
 * \param[out] contents  Where to store file contents
 *
 * \return Standard Pacemaker return code
 * \note On success, the caller is responsible for freeing contents.
 */
int
pcmk__file_contents(const char *filename, char **contents)
{
    FILE *fp;
    int length, read_len;
    int rc = pcmk_rc_ok;

    if ((filename == NULL) || (contents == NULL)) {
        return EINVAL;
    }

    fp = fopen(filename, "r");
    if ((fp == NULL) || (fseek(fp, 0L, SEEK_END) < 0)) {
        rc = errno;
        goto bail;
    }

    length = ftell(fp);
    if (length < 0) {
        rc = errno;
        goto bail;
    }

    if (length == 0) {
        *contents = NULL;
    } else {
        *contents = calloc(length + 1, sizeof(char));
        if (*contents == NULL) {
            rc = errno;
            goto bail;
        }

        errno = 0;

        rewind(fp);
        if (errno != 0) {
            rc = errno;
            goto bail;
        }

        read_len = fread(*contents, 1, length, fp);
        if (read_len != length) {
            free(*contents);
            *contents = NULL;
            rc = EIO;
        } else {
            /* Coverity thinks *contents isn't null-terminated. It doesn't
             * understand calloc().
             */
            (*contents)[length] = '\0';
        }
    }

bail:
    if (fp != NULL) {
        fclose(fp);
    }
    return rc;
}

/*!
 * \internal
 * \brief Write text to a file, flush and sync it to disk, then close the file
 *
 * \param[in] fd        File descriptor opened for writing
 * \param[in] contents  String to write to file
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__write_sync(int fd, const char *contents)
{
    int rc = 0;
    FILE *fp = fdopen(fd, "w");

    if (fp == NULL) {
        return errno;
    }
    if ((contents != NULL) && (fprintf(fp, "%s", contents) < 0)) {
        rc = EIO;
    }
    if (fflush(fp) != 0) {
        rc = errno;
    }
    if (fsync(fileno(fp)) < 0) {
        rc = errno;
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
 * \return Standard Pacemaker return code
 */
int
pcmk__set_nonblocking(int fd)
{
    int flag = fcntl(fd, F_GETFL);

    if (flag < 0) {
        return errno;
    }
    if (fcntl(fd, F_SETFL, flag | O_NONBLOCK) < 0) {
        return errno;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Get directory name for temporary files
 *
 * Return the value of the TMPDIR environment variable if it is set to a
 * full path, otherwise return "/tmp".
 *
 * \return Name of directory to be used for temporary files
 */
const char *
pcmk__get_tmpdir(void)
{
    const char *dir = getenv("TMPDIR");

    return (dir && (*dir == '/'))? dir : "/tmp";
}

/*!
 * \internal
 * \brief Close open file descriptors
 *
 * Close all file descriptors (except optionally stdin, stdout, and stderr),
 * which is a best practice for a new child process forked for the purpose of
 * executing an external program.
 *
 * \param[in] bool  If true, close stdin, stdout, and stderr as well
 */
void
pcmk__close_fds_in_child(bool all)
{
    DIR *dir;
    struct rlimit rlim;
    rlim_t max_fd;
    int min_fd = (all? 0 : (STDERR_FILENO + 1));

    /* Find the current process's (soft) limit for open files. getrlimit()
     * should always work, but have a fallback just in case.
     */
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        max_fd = rlim.rlim_cur - 1;
    } else {
        long conf_max = sysconf(_SC_OPEN_MAX);

        max_fd = (conf_max > 0)? conf_max : 1024;
    }

    /* First try /proc.  If that returns NULL (either because opening the
     * directory failed, or because procfs isn't supported on this platform),
     * fall back to /dev/fd.
     */
    dir = pcmk__procfs_fd_dir();
    if (dir == NULL) {
        dir = opendir("/dev/fd");
    }

    if (dir != NULL) {
        struct dirent *entry;
        int dir_fd = dirfd(dir);

        while ((entry = readdir(dir)) != NULL) {
            int lpc = atoi(entry->d_name);

            /* How could one of these entries be higher than max_fd, you ask?
             * It isn't possible in normal operation, but when run under
             * valgrind, valgrind can open high-numbered file descriptors for
             * its own use that are higher than the process's soft limit.
             * These will show up in the fd directory but aren't closable.
             */
            if ((lpc >= min_fd) && (lpc <= max_fd) && (lpc != dir_fd)) {
                close(lpc);
            }
        }
        closedir(dir);
        return;
    }

    /* If no fd directory is available, iterate over all possible descriptors.
     * This is less efficient due to the overhead of many system calls.
     */
    for (int lpc = max_fd; lpc >= min_fd; lpc--) {
        close(lpc);
    }
}

/*!
 * \brief Duplicate a file path, inserting a prefix if not absolute
 *
 * \param[in] filename  File path to duplicate
 * \param[in] dirname   If filename is not absolute, prefix to add
 *
 * \return Newly allocated memory with full path (guaranteed non-NULL)
 */
char *
pcmk__full_path(const char *filename, const char *dirname)
{
    pcmk__assert(filename != NULL);

    if (filename[0] == '/') {
        return pcmk__str_copy(filename);
    }
    pcmk__assert(dirname != NULL);
    return crm_strdup_printf("%s/%s", dirname, filename);
}
