/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>

#if HAVE_LINUX_PROCFS
/*!
 * \internal
 * \brief Return name of /proc file containing the CIB daemon's load statistics
 *
 * \return Newly allocated memory with file name on success, NULL otherwise
 *
 * \note It is the caller's responsibility to free the return value.
 *       This will return NULL if the daemon is being run via valgrind.
 *       This should be called only on Linux systems.
 */
static char *
find_cib_loadfile(const char *server)
{
    pid_t pid = pcmk__procfs_pid_of(server);

    if (pid == 0) {
        return NULL;
    }
    return pcmk__assert_asprintf("/proc/%lld/stat", (long long) pid);
}

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
pcmk__procfs_process_info(const struct dirent *entry, char *name, pid_t *pid)
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
#endif // HAVE_LINUX_PROCFS

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
#if HAVE_LINUX_PROCFS
    DIR *dp;
    struct dirent *entry;
    pid_t pid = 0;
    char entry_name[64] = { 0 };

    dp = opendir("/proc");
    if (dp == NULL) {
        pcmk__notice("Can not read /proc directory to track existing "
                     "components");
        return 0;
    }

    while ((entry = readdir(dp)) != NULL) {
        if ((pcmk__procfs_process_info(entry, entry_name, &pid) == pcmk_rc_ok)
            && pcmk__str_eq(entry_name, name, pcmk__str_casei)
            && (pcmk__pid_active(pid, NULL) == pcmk_rc_ok)) {

            pcmk__info("Found %s active as process %lld", name,
                       (long long) pid);
            break;
        }
        pid = 0;
    }
    closedir(dp);
    return pid;
#else
    return 0;
#endif // HAVE_LINUX_PROCFS
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
#if HAVE_LINUX_PROCFS
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
#else
    return 1;
#endif // HAVE_LINUX_PROCFS
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

/*!
 * \internal
 * \brief Return an open handle on the directory containing links to open file
 *        descriptors, or NULL on error
 */
DIR *
pcmk__procfs_fd_dir(void)
{
    DIR *dir = NULL;

    /* /proc/self/fd (on Linux) or /dev/fd (on most OSes) contains symlinks to
     * all open files for the current process, named as the file descriptor.
     * Use this if available, because it's more efficient than a shotgun
     * approach to closing descriptors.
     */
#if HAVE_LINUX_PROCFS
    dir = opendir("/proc/self/fd");
#endif // HAVE_LINUX_PROCFS

    return dir;
}

/*!
 * \internal
 * \brief Trigger a sysrq command if supported on current platform
 *
 * \param[in] t  Sysrq command to trigger
 */
void
pcmk__sysrq_trigger(char t)
{
#if HAVE_LINUX_PROCFS
    // Root can always write here, regardless of kernel.sysrq value
    FILE *procf = fopen("/proc/sysrq-trigger", "a");

    if (procf == NULL) {
        pcmk__warn("Could not open sysrq-trigger: %s", strerror(errno));
    } else {
        fprintf(procf, "%c\n", t);
        fclose(procf);
    }
#endif // HAVE_LINUX_PROCFS
}

bool
pcmk__throttle_cib_load(const char *server, float *load)
{
/* /proc/[pid]/stat
 *
 * Status information about the process.  This is used by ps(1).  It is defined
 * in /usr/src/linux/fs/proc/array.c.
 *
 * The fields, in order, with their proper scanf(3) format specifiers, are:
 *
 * pid %d      (1)  The process ID.
 * comm %s     (2)  The filename of the executable, in parentheses.  This is
 *                  visible whether or not the executable is swapped out.
 * state %c    (3)  One character from the string "RSDZTW" where R is running,
 *                  S is sleeping in an interruptible wait, D is waiting in
 *                  uninterruptible disk sleep, Z is zombie, T is traced or
 *                  stopped (on a signal), and W is paging.
 * ppid %d     (4)  The PID of the parent.
 * pgrp %d     (5)  The process group ID of the process.
 * session %d  (6)  The session ID of the process.
 * tty_nr %d   (7)  The controlling terminal of the process.  (The minor device
 *                  number is contained in the combination of bits 31 to 20 and
 *                  7 to 0; the major device number is in bits 15 to 8.)
 * tpgid %d    (8)  The ID of the foreground process group of the controlling
 *                  terminal of the process.
 * flags %u    (9)  The kernel flags word of the process.  For bit meanings, see
 *                  the PF_* defines in the Linux kernel source file include/linux/sched.h.
 *                  Details depend on the kernel version.
 * minflt %lu  (10) The number of minor faults the process has made which have
 *                  not required loading a memory page from disk.
 * cminflt %lu (11) The number of minor faults that the process's waited-for
 *                  children have made.
 * majflt %lu  (12) The number of major faults the process has made which have
 *                  required loading a memory page from disk.
 * cmajflt %lu (13) The number of major faults that the process's waited-for
 *                  children have made.
 * utime %lu   (14) Amount of time that this process has been scheduled in user
 *                  mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).
 *                  This includes guest time, guest_time (time spent running a
 *                  virtual CPU, see below), so that applications that are not
 *                  aware of the guest time field do not lose that time from
 *                  their calculations.
 * stime %lu   (15) Amount of time that this process has been scheduled in
 *                  kernel mode, measured in clock ticks (divide by sysconf(_SC_CLK_TCK)).
 */

#if HAVE_LINUX_PROCFS
    static char *loadfile = NULL;
    static time_t last_call = 0;
    static long ticks_per_s = 0;
    static unsigned long last_utime, last_stime;

    char buffer[64*1024];
    FILE *stream = NULL;
    time_t now = time(NULL);

    if (load == NULL) {
        return false;
    } else {
        *load = 0.0;
    }

    if (loadfile == NULL) {
        last_call = 0;
        last_utime = 0;
        last_stime = 0;

        loadfile = find_cib_loadfile(server);
        if (loadfile == NULL) {
            pcmk__warn("Couldn't find CIB load file");
            return false;
        }

        ticks_per_s = sysconf(_SC_CLK_TCK);
        pcmk__trace("Found %s", loadfile);
    }

    stream = fopen(loadfile, "r");
    if (stream == NULL) {
        int rc = errno;

        pcmk__warn("Couldn't read %s: %s (%d)", loadfile, pcmk_rc_str(rc), rc);
        free(loadfile);
        loadfile = NULL;
        return false;
    }

    if (fgets(buffer, sizeof(buffer), stream) != NULL) {
        char *comm = pcmk__assert_alloc(1, 256);
        char state = 0;
        int rc = 0, pid = 0, ppid = 0, pgrp = 0, session = 0, tty_nr = 0, tpgid = 0;
        unsigned long flags = 0, minflt = 0, cminflt = 0, majflt = 0, cmajflt = 0, utime = 0, stime = 0;

        rc = sscanf(buffer, "%d %[^ ] %c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu",
                    &pid, comm, &state, &ppid, &pgrp, &session, &tty_nr, &tpgid,
                    &flags, &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime);
        free(comm);

        if (rc != 15) {
            pcmk__err("Only %d of 15 fields found in %s", rc, loadfile);
            fclose(stream);
            return false;

        } else if ((last_call > 0) && (last_call < now) && (last_utime <= utime) &&
                   (last_stime <= stime)) {
            time_t elapsed = now - last_call;
            unsigned long delta_utime = utime - last_utime;
            unsigned long delta_stime = stime - last_stime;

            *load = delta_utime + delta_stime; /* Cast to a float before division */
            *load /= ticks_per_s;
            *load /= elapsed;
            pcmk__debug("cib load: %f (%lu ticks in %llds)", *load,
                        (delta_utime + delta_stime), (long long) elapsed);

        } else {
            pcmk__debug("Init %lu + %lu ticks at %lld (%lu tps)", utime, stime,
                        (long long) now, ticks_per_s);
        }

        last_call = now;
        last_utime = utime;
        last_stime = stime;

        fclose(stream);
        return true;
    }

    fclose(stream);
#endif // HAVE_LINUX_PROCFS
    return false;
}

bool
pcmk__throttle_load_avg(float *load)
{
#if HAVE_LINUX_PROCFS
    char buffer[256];
    FILE *stream = NULL;
    const char *loadfile = "/proc/loadavg";

    if (load == NULL) {
        return false;
    }

    stream = fopen(loadfile, "r");
    if (stream == NULL) {
        int rc = errno;
        pcmk__warn("Couldn't read %s: %s (%d)", loadfile, pcmk_rc_str(rc), rc);
        return false;
    }

    if (fgets(buffer, sizeof(buffer), stream) != NULL) {
        char *nl = strstr(buffer, "\n");

        /* Grab the 1-minute average, ignore the rest */
        *load = strtof(buffer, NULL);
        if (nl != NULL) {
            nl[0] = 0;
        }

        fclose(stream);
        return true;
    }

    fclose(stream);
#endif // HAVE_LINUX_PROCFS
    return false;
}
