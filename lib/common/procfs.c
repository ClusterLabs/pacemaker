/*
 * Copyright (C) 2015 Andrew Beekhof <andrew@beekhof.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

/*!
 * \internal
 * \brief Get process ID and name associated with a /proc directory entry
 *
 * \param[in]  entry    Directory entry (must be result of readdir() on /proc)
 * \param[out] name     If not NULL, a char[64] to hold the process name
 * \param[out] pid      If not NULL, will be set to process ID of entry
 *
 * \return 0 on success, -1 if entry is not for a process or info not found
 *
 * \note This should be called only on Linux systems, as not all systems that
 *       support /proc store process names and IDs in the same way.
 */
int
crm_procfs_process_info(struct dirent *entry, char *name, int *pid)
{
    int fd, local_pid;
    FILE *file;
    struct stat statbuf;
    char key[16] = { 0 }, procpath[128] = { 0 };

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
        *pid = local_pid;
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
        if ((fscanf(file, "%15s%63s", key, name) != 2)
            || safe_str_neq(key, "Name:")) {
            fclose(file);
            return -1;
        }
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
int
crm_procfs_pid_of(const char *name)
{
    DIR *dp;
    struct dirent *entry;
    int pid = 0;
    char entry_name[64] = { 0 };

    dp = opendir("/proc");
    if (dp == NULL) {
        crm_notice("Can not read /proc directory to track existing components");
        return 0;
    }

    while ((entry = readdir(dp)) != NULL) {
        if ((crm_procfs_process_info(entry, entry_name, &pid) == 0)
            && safe_str_eq(entry_name, name)
            && (crm_pid_active(pid, NULL) == 1)) {

            crm_info("Found %s active as process %d", name, pid);
            break;
        }
        pid = 0;
    }
    closedir(dp);
    return pid;
}
