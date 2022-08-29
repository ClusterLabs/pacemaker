/*
 * Copyright 2015-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>

/*!
 * \internal
 * \brief Get process ID and name associated with a /proc directory entry
 *
 * \param[in]  entry    Directory entry (must be result of readdir() on /proc)
 * \param[out] name     If not NULL, a char[16] to hold the process name
 * \param[out] pid      If not NULL, will be set to process ID of entry
 *
 * \return Standard Pacemaker return code
 * \note This should be called only on Linux systems, as not all systems that
 *       support /proc store process names and IDs in the same way. The kernel
 *       limits the process name to the first 15 characters (plus terminator).
 *       It would be nice if there were a public kernel API constant for that
 *       limit, but there isn't.
 */
static int
pcmk__procfs_process_info(struct dirent *entry, char *name, pid_t *pid)
{
    int fd, local_pid;
    FILE *file;
    struct stat statbuf;
    char procpath[128] = { 0 };

    /* We're only interested in entries whose name is a PID,
     * so skip anything non-numeric or that is too long.
     *
     * 114 = 128 - strlen("/proc/") - strlen("/status") - 1
     */
    local_pid = atoi(entry->d_name);
    if ((local_pid <= 0) || (strlen(entry->d_name) > 114)) {
        return -1;
    }
    if (pid) {
        *pid = (pid_t) local_pid;
    }

    /* Get this entry's file information */
    strcpy(procpath, "/proc/");
    strcat(procpath, entry->d_name);
    fd = open(procpath, O_RDONLY);
    if (fd < 0 ) {
        return -1;
    }
    if (fstat(fd, &statbuf) < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    /* We're only interested in subdirectories */
    if (!S_ISDIR(statbuf.st_mode)) {
        return -1;
    }

    /* Read the first entry ("Name:") from the process's status file.
     * We could handle the valgrind case if we parsed the cmdline file
     * instead, but that's more of a pain than it's worth.
     */
    if (name != NULL) {
        strcat(procpath, "/status");
        file = fopen(procpath, "r");
        if (!file) {
            return -1;
        }
        if (fscanf(file, "Name:\t%15[^\n]", name) != 1) {
            fclose(file);
            return -1;
        }
        name[15] = 0;
        fclose(file);
    }

    return 0;
}

/*!
 * \internal
 * \brief Return process ID of a named process
 *
 * \param[in] name  Process name (as used in /proc/.../status)
 *
 * \return Process ID of named process if running, 0 otherwise
 *
 * \note This will return 0 if the process is being run via valgrind.
 *       This should be called only on Linux systems.
 */
pid_t
pcmk__procfs_pid_of(const char *name)
{
    DIR *dp;
    struct dirent *entry;
    pid_t pid = 0;
    char entry_name[64] = { 0 };

    dp = opendir("/proc");
    if (dp == NULL) {
        crm_notice("Can not read /proc directory to track existing components");
        return 0;
    }

    while ((entry = readdir(dp)) != NULL) {
        if ((pcmk__procfs_process_info(entry, entry_name, &pid) == pcmk_rc_ok)
            && pcmk__str_eq(entry_name, name, pcmk__str_casei)
            && (pcmk__pid_active(pid, NULL) == pcmk_rc_ok)) {

            crm_info("Found %s active as process %lld", name, (long long) pid);
            break;
        }
        pid = 0;
    }
    closedir(dp);
    return pid;
}

/*!
 * \internal
 * \brief Calculate number of logical CPU cores from procfs
 *
 * \return Number of cores (or 1 if unable to determine)
 */
unsigned int
pcmk__procfs_num_cores(void)
{
    int cores = 0;
    FILE *stream = NULL;

    /* Parse /proc/stat instead of /proc/cpuinfo because it's smaller */
    stream = fopen("/proc/stat", "r");
    if (stream == NULL) {
        crm_perror(LOG_INFO, "Could not open /proc/stat");
    } else {
        char buffer[2048];

        while (fgets(buffer, sizeof(buffer), stream)) {
            if (pcmk__starts_with(buffer, "cpu") && isdigit(buffer[3])) {
                ++cores;
            }
        }
        fclose(stream);
    }
    return cores? cores : 1;
}

/*!
 * \internal
 * \brief Get the executable path corresponding to a process ID
 *
 * \param[in]  pid        Process ID to check
 * \param[out] path       Where to store executable path
 * \param[in]  path_size  Size of \p path in characters (ideally PATH_MAX)
 *
 * \return Standard Pacemaker error code (as possible errno values from
 *         readlink())
 */
int
pcmk__procfs_pid2path(pid_t pid, char path[], size_t path_size)
{
#if HAVE_LINUX_PROCFS
    char procfs_exe_path[PATH_MAX];
    ssize_t link_rc;

    if (snprintf(procfs_exe_path, PATH_MAX, "/proc/%lld/exe",
                 (long long) pid) >= PATH_MAX) {
        return ENAMETOOLONG; // Truncated (shouldn't be possible in practice)
    }

    link_rc = readlink(procfs_exe_path, path, path_size - 1);
    if (link_rc < 0) {
        return errno;
    } else if (link_rc >= (path_size - 1)) {
        return ENAMETOOLONG;
    }

    path[link_rc] = '\0';
    return pcmk_rc_ok;
#else
    return EOPNOTSUPP;
#endif // HAVE_LINUX_PROCFS
}

/*!
 * \internal
 * \brief Check whether process ID information is available from procfs
 *
 * \return true if process ID information is available, otherwise false
 */
bool
pcmk__procfs_has_pids(void)
{
#if HAVE_LINUX_PROCFS
    static bool have_pids = false;
    static bool checked = false;

    if (!checked) {
        char path[PATH_MAX];

        have_pids = pcmk__procfs_pid2path(getpid(), path, sizeof(path)) == pcmk_rc_ok;
        checked = true;
    }
    return have_pids;
#else
    return false;
#endif // HAVE_LINUX_PROCFS
}
