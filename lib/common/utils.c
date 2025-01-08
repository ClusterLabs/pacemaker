/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/stat.h>
#include <sys/utsname.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <pwd.h>
#include <time.h>
#include <libgen.h>
#include <signal.h>
#include <grp.h>

#include <qb/qbdefs.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/cib/internal.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/common/ipc.h>
#include <crm/common/iso8601.h>
#include <crm/common/mainloop.h>
#include <libxml2/libxml/relaxng.h>

#include "crmcommon_private.h"

CRM_TRACE_INIT_DATA(common);

bool pcmk__config_has_error = false;
bool pcmk__config_has_warning = false;
char *crm_system_name = NULL;

/*!
 * \brief Free all memory used by libcrmcommon
 *
 * Free all global memory allocated by the libcrmcommon library. This should be
 * called before exiting a process that uses the library, and the process should
 * not call any libcrmcommon or libxml2 APIs after calling this one.
 */
void
pcmk_common_cleanup(void)
{
    // @TODO This isn't really everything, move all cleanup here
    mainloop_cleanup();
    pcmk__xml_cleanup();
    pcmk__free_common_logger();
    qb_log_fini(); // Don't log anything after this point

    free(crm_system_name);
    crm_system_name = NULL;
}

bool
pcmk__is_user_in_group(const char *user, const char *group)
{
    struct group *grent;
    char **gr_mem;

    if (user == NULL || group == NULL) {
        return false;
    }
    
    setgrent();
    while ((grent = getgrent()) != NULL) {
        if (grent->gr_mem == NULL) {
            continue;
        }

        if(strcmp(group, grent->gr_name) != 0) {
            continue;
        }

        gr_mem = grent->gr_mem;
        while (*gr_mem != NULL) {
            if (!strcmp(user, *gr_mem++)) {
                endgrent();
                return true;
            }
        }
    }
    endgrent();
    return false;
}

int
crm_user_lookup(const char *name, uid_t * uid, gid_t * gid)
{
    int rc = pcmk_ok;
    char *buffer = NULL;
    struct passwd pwd;
    struct passwd *pwentry = NULL;

    buffer = calloc(1, PCMK__PW_BUFFER_LEN);
    if (buffer == NULL) {
        return -ENOMEM;
    }

    rc = getpwnam_r(name, &pwd, buffer, PCMK__PW_BUFFER_LEN, &pwentry);
    if (pwentry) {
        if (uid) {
            *uid = pwentry->pw_uid;
        }
        if (gid) {
            *gid = pwentry->pw_gid;
        }
        crm_trace("User %s has uid=%d gid=%d", name, pwentry->pw_uid, pwentry->pw_gid);

    } else {
        rc = rc? -rc : -EINVAL;
        crm_info("User %s lookup: %s", name, pcmk_strerror(rc));
    }

    free(buffer);
    return rc;
}

/*!
 * \brief Get user and group IDs of pacemaker daemon user
 *
 * \param[out] uid  If non-NULL, where to store daemon user ID
 * \param[out] gid  If non-NULL, where to store daemon group ID
 *
 * \return pcmk_ok on success, -errno otherwise
 */
int
pcmk_daemon_user(uid_t *uid, gid_t *gid)
{
    static uid_t daemon_uid;
    static gid_t daemon_gid;
    static bool found = false;
    int rc = pcmk_ok;

    if (!found) {
        rc = crm_user_lookup(CRM_DAEMON_USER, &daemon_uid, &daemon_gid);
        if (rc == pcmk_ok) {
            found = true;
        }
    }
    if (found) {
        if (uid) {
            *uid = daemon_uid;
        }
        if (gid) {
            *gid = daemon_gid;
        }
    }
    return rc;
}

/*!
 * \internal
 * \brief Return the integer equivalent of a portion of a string
 *
 * \param[in]  text      Pointer to beginning of string portion
 * \param[out] end_text  This will point to next character after integer
 */
static int
version_helper(const char *text, const char **end_text)
{
    int atoi_result = -1;

    pcmk__assert(end_text != NULL);

    errno = 0;

    if (text != NULL && text[0] != 0) {
        /* seemingly sacrificing const-correctness -- because while strtol
           doesn't modify the input, it doesn't want to artificially taint the
           "end_text" pointer-to-pointer-to-first-char-in-string with constness
           in case the input wasn't actually constant -- by semantic definition
           not a single character will get modified so it shall be perfectly
           safe to make compiler happy with dropping "const" qualifier here */
        atoi_result = (int) strtol(text, (char **) end_text, 10);

        if (errno == EINVAL) {
            crm_err("Conversion of '%s' %c failed", text, text[0]);
            atoi_result = -1;
        }
    }
    return atoi_result;
}

/*
 * version1 < version2 : -1
 * version1 = version2 :  0
 * version1 > version2 :  1
 */
int
compare_version(const char *version1, const char *version2)
{
    int rc = 0;
    int lpc = 0;
    const char *ver1_iter, *ver2_iter;

    if (version1 == NULL && version2 == NULL) {
        return 0;
    } else if (version1 == NULL) {
        return -1;
    } else if (version2 == NULL) {
        return 1;
    }

    ver1_iter = version1;
    ver2_iter = version2;

    while (1) {
        int digit1 = 0;
        int digit2 = 0;

        lpc++;

        if (ver1_iter == ver2_iter) {
            break;
        }

        if (ver1_iter != NULL) {
            digit1 = version_helper(ver1_iter, &ver1_iter);
        }

        if (ver2_iter != NULL) {
            digit2 = version_helper(ver2_iter, &ver2_iter);
        }

        if (digit1 < digit2) {
            rc = -1;
            break;

        } else if (digit1 > digit2) {
            rc = 1;
            break;
        }

        if (ver1_iter != NULL && *ver1_iter == '.') {
            ver1_iter++;
        }
        if (ver1_iter != NULL && *ver1_iter == '\0') {
            ver1_iter = NULL;
        }

        if (ver2_iter != NULL && *ver2_iter == '.') {
            ver2_iter++;
        }
        if (ver2_iter != NULL && *ver2_iter == 0) {
            ver2_iter = NULL;
        }
    }

    if (rc == 0) {
        crm_trace("%s == %s (%d)", version1, version2, lpc);
    } else if (rc < 0) {
        crm_trace("%s < %s (%d)", version1, version2, lpc);
    } else if (rc > 0) {
        crm_trace("%s > %s (%d)", version1, version2, lpc);
    }

    return rc;
}

/*!
 * \internal
 * \brief Convert the current process to a daemon process
 *
 * Fork a child process, exit the parent, create a PID file with the current
 * process ID, and close the standard input/output/error file descriptors.
 * Exit instead if a daemon is already running and using the PID file.
 *
 * \param[in] name     Daemon executable name
 * \param[in] pidfile  File name to use as PID file
 */
void
pcmk__daemonize(const char *name, const char *pidfile)
{
    int rc;
    pid_t pid;

    /* Check before we even try... */
    rc = pcmk__pidfile_matches(pidfile, 1, name, &pid);
    if ((rc != pcmk_rc_ok) && (rc != ENOENT)) {
        crm_err("%s: already running [pid %lld in %s]",
                name, (long long) pid, pidfile);
        printf("%s: already running [pid %lld in %s]\n",
               name, (long long) pid, pidfile);
        crm_exit(CRM_EX_ERROR);
    }

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "%s: could not start daemon\n", name);
        crm_perror(LOG_ERR, "fork");
        crm_exit(CRM_EX_OSERR);

    } else if (pid > 0) {
        crm_exit(CRM_EX_OK);
    }

    rc = pcmk__lock_pidfile(pidfile, name);
    if (rc != pcmk_rc_ok) {
        crm_err("Could not lock '%s' for %s: %s " QB_XS " rc=%d",
                pidfile, name, pcmk_rc_str(rc), rc);
        printf("Could not lock '%s' for %s: %s (%d)\n",
               pidfile, name, pcmk_rc_str(rc), rc);
        crm_exit(CRM_EX_ERROR);
    }

    umask(S_IWGRP | S_IWOTH | S_IROTH);

    close(STDIN_FILENO);
    pcmk__open_devnull(O_RDONLY);   // stdin (fd 0)

    close(STDOUT_FILENO);
    pcmk__open_devnull(O_WRONLY);   // stdout (fd 1)

    close(STDERR_FILENO);
    pcmk__open_devnull(O_WRONLY);   // stderr (fd 2)
}

#ifdef HAVE_UUID_UUID_H
#  include <uuid/uuid.h>
#endif

char *
crm_generate_uuid(void)
{
    unsigned char uuid[16];
    char *buffer = malloc(37);  /* Including NUL byte */

    pcmk__mem_assert(buffer);
    uuid_generate(uuid);
    uuid_unparse(uuid, buffer);
    return buffer;
}

/*!
 * \internal
 * \brief Sleep for given milliseconds
 *
 * \param[in] ms  Time to sleep
 *
 * \note The full time might not be slept if a signal is received.
 */
void
pcmk__sleep_ms(unsigned int ms)
{
    // @TODO Impose a sane maximum sleep to avoid hanging a process for long
    //CRM_CHECK(ms <= MAX_SLEEP, ms = MAX_SLEEP);

    // Use sleep() for any whole seconds
    if (ms >= 1000) {
        sleep(ms / 1000);
        ms -= ms / 1000;
    }

    if (ms == 0) {
        return;
    }

#if defined(HAVE_NANOSLEEP)
    // nanosleep() is POSIX-2008, so prefer that
    {
        struct timespec req = { .tv_sec = 0, .tv_nsec = (long) (ms * 1000000) };

        nanosleep(&req, NULL);
    }
#elif defined(HAVE_USLEEP)
    // usleep() is widely available, though considered obsolete
    usleep((useconds_t) ms);
#else
    // Otherwise use a trick with select() timeout
    {
        struct timeval tv = { .tv_sec = 0, .tv_usec = (suseconds_t) ms };

        select(0, NULL, NULL, NULL, &tv);
    }
#endif
}

/*!
 * \internal
 * \brief Add a timer
 *
 * \param[in] interval_ms The interval for the function to be called, in ms
 * \param[in] fn          The function to be called
 * \param[in] data        Data to be passed to fn (can be NULL)
 *
 * \return The ID of the event source
 */
guint
pcmk__create_timer(guint interval_ms, GSourceFunc fn, gpointer data)
{
    pcmk__assert(interval_ms != 0 && fn != NULL);

    if (interval_ms % 1000 == 0) {
        /* In case interval_ms is 0, the call to pcmk__timeout_ms2s ensures
         * an interval of one second.
         */
        return g_timeout_add_seconds(pcmk__timeout_ms2s(interval_ms), fn, data);
    } else {
        return g_timeout_add(interval_ms, fn, data);
    }
}

/*!
 * \internal
 * \brief Convert milliseconds to seconds
 *
 * \param[in] timeout_ms The interval, in ms
 *
 * \return If \p timeout_ms is 0, return 0.  Otherwise, return the number of
 *         seconds, rounded to the nearest integer, with a minimum of 1.
 */
guint
pcmk__timeout_ms2s(guint timeout_ms)
{
    guint quot, rem;

    if (timeout_ms == 0) {
        return 0;
    } else if (timeout_ms < 1000) {
        return 1;
    }

    quot = timeout_ms / 1000;
    rem = timeout_ms % 1000;

    if (rem >= 500) {
        quot += 1;
    }

    return quot;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <gnutls/gnutls.h>          // gnutls_global_init(), etc.

#include <crm/common/util_compat.h>

static void
_gnutls_log_func(int level, const char *msg)
{
    crm_trace("%s", msg);
}

void
crm_gnutls_global_init(void)
{
    signal(SIGPIPE, SIG_IGN);
    gnutls_global_init();
    gnutls_global_set_log_level(8);
    gnutls_global_set_log_function(_gnutls_log_func);
}

/*!
 * \brief Check whether string represents a client name used by cluster daemons
 *
 * \param[in] name  String to check
 *
 * \return true if name is standard client name used by daemons, false otherwise
 *
 * \note This is provided by the client, and so cannot be used by itself as a
 *       secure means of authentication.
 */
bool
crm_is_daemon_name(const char *name)
{
    return pcmk__str_any_of(name,
                            "attrd",
                            CRM_SYSTEM_CIB,
                            CRM_SYSTEM_CRMD,
                            CRM_SYSTEM_DC,
                            CRM_SYSTEM_LRMD,
                            CRM_SYSTEM_MCP,
                            CRM_SYSTEM_PENGINE,
                            CRM_SYSTEM_TENGINE,
                            "pacemaker-attrd",
                            "pacemaker-based",
                            "pacemaker-controld",
                            "pacemaker-execd",
                            "pacemaker-fenced",
                            "pacemaker-remoted",
                            "pacemaker-schedulerd",
                            "stonith-ng",
                            "stonithd",
                            NULL);
}

// LCOV_EXCL_STOP
// End deprecated API
