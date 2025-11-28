/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/stat.h>
#include <sys/utsname.h>

#include <stdbool.h>
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
#include <libxml/parser.h>              // xmlCleanupParser()
#include <libxml2/libxml/relaxng.h>

#include "crmcommon_private.h"

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
    pcmk__schema_cleanup();
    pcmk__free_logging_data();

    free(crm_system_name);
    crm_system_name = NULL;

    // Clean up external library global state
    qb_log_fini(); // Don't log anything after this point
    xmlCleanupParser();
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
pcmk__lookup_user(const char *name, uid_t *uid, gid_t *gid)
{
    struct passwd *pwentry = NULL;

    CRM_CHECK(name != NULL, return EINVAL);

    // getpwnam() is not thread-safe, but Pacemaker is single-threaded
    errno = 0;
    pwentry = getpwnam(name);
    if (pwentry == NULL) {
        /* Either an error occurred or no passwd entry was found.
         *
         * The value of errno is implementation-dependent if no passwd entry is
         * found. The POSIX specification does not consider it an error.
         * POSIX.1-2008 specifies that errno shall not be changed in this case,
         * while POSIX.1-2001 does not specify the value of errno in this case.
         * The man page on Linux notes that a variety of values have been
         * observed in practice. So an implementation may set errno to an
         * arbitrary value, despite the POSIX specification.
         *
         * However, if pwentry == NULL and errno == 0, then we know that no
         * matching entry was found and there was no error. So we default to
         * ENOENT as our return code.
         */
        return ((errno != 0)? errno : ENOENT);
    }

    if (uid != NULL) {
        *uid = pwentry->pw_uid;
    }
    if (gid != NULL) {
        *gid = pwentry->pw_gid;
    }
    pcmk__trace("User %s has uid=%lld gid=%lld", name,
                (long long) pwentry->pw_uid, (long long) pwentry->pw_gid);

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Get user and group IDs of Pacemaker daemon user
 *
 * \param[out] uid  Where to store daemon user ID (can be \c NULL)
 * \param[out] gid  Where to store daemon group ID (can be \c NULL)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__daemon_user(uid_t *uid, gid_t *gid)
{
    static uid_t daemon_uid = 0;
    static gid_t daemon_gid = 0;
    static bool found = false;

    if (!found) {
        int rc = pcmk__lookup_user(CRM_DAEMON_USER, &daemon_uid, &daemon_gid);

        if (rc != pcmk_rc_ok) {
            return rc;
        }
        found = true;
    }

    if (uid != NULL) {
        *uid = daemon_uid;
    }
    if (gid != NULL) {
        *gid = daemon_gid;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Compare two version strings to determine which one is higher
 *
 * A valid version string is of the form specified by the regex
 * <tt>[0-9]+(\.[0-9]+)*</tt>.
 *
 * Leading whitespace and trailing garbage are allowed and ignored. Anything
 * that doesn't match the regex above is considered garbage.
 *
 * For each string, we get all segments until the first invalid character. A
 * segment is a series of digits, and segments are delimited by a single dot.
 * The two strings are compared segment by segment, until either we find a
 * difference or we've processed all segments in both strings.
 *
 * If one string runs out of segments to compare before the other string does,
 * we treat it as if it has enough padding \c "0" segments to finish the
 * comparisons.
 *
 * Segments are compared by calling \c strtoll() to parse them to long long
 * integers and then performing standard integer comparison.
 *
 * \param[in] version1  First version to compare
 * \param[in] version2  Second version to compare
 *
 * \retval -1  if \p version1 evaluates to a lower version than \p version2
 * \retval  1  if \p version1 evaluates to a higher version than \p version2
 * \retval  0  if \p version1 and \p version2 evaluate to an equal version
 *
 * \note Each version segment's parsed value must fit into a <tt>long long</tt>.
 */
int
pcmk__compare_versions(const char *version1, const char *version2)
{
    int rc = 0;
    gchar *match1 = NULL;
    gchar *match2 = NULL;
    gchar **segments1 = NULL;
    gchar **segments2 = NULL;
    GRegex *regex = NULL;

    if (pcmk__str_eq(version1, version2, pcmk__str_none)) {
        goto done;
    }

    // Ignore leading whitespace and trailing garbage
    regex = g_regex_new("^\\s*(\\d+(?:\\.\\d+)*)", 0, 0, NULL);

    if (!pcmk__str_empty(version1)) {
        GMatchInfo *match_info = NULL;

        if (g_regex_match(regex, version1, 0, &match_info)) {
            match1 = g_match_info_fetch(match_info, 1);
        }
        g_match_info_unref(match_info);
    }
    if (!pcmk__str_empty(version2)) {
        GMatchInfo *match_info = NULL;

        if (g_regex_match(regex, version2, 0, &match_info)) {
            match2 = g_match_info_fetch(match_info, 1);
        }
        g_match_info_unref(match_info);
    }

    segments1 = g_strsplit(pcmk__s(match1, ""), ".", 0);
    segments2 = g_strsplit(pcmk__s(match2, ""), ".", 0);

    for (gchar **segment1 = segments1, **segment2 = segments2;
         (*segment1 != NULL) || (*segment2 != NULL); ) {

        long long value1 = 0;
        long long value2 = 0;

        if (*segment1 != NULL) {
            // Make Coverity happy by casting to void
            (void) pcmk__scan_ll(*segment1, &value1, 0);
            segment1++;
        }
        if (*segment2 != NULL) {
            (void) pcmk__scan_ll(*segment2, &value2, 0);
            segment2++;
        }

        if (value1 < value2) {
            pcmk__trace("%s < %s", version1, version2);
            rc = -1;
            goto done;
        }
        if (value1 > value2) {
            pcmk__trace("%s > %s", version1, version2);
            rc = 1;
            goto done;
        }
    }

    pcmk__trace("%s == %s", version1, version2);

done:
    g_free(match1);
    g_free(match2);
    g_strfreev(segments1);
    g_strfreev(segments2);
    if (regex != NULL) {
        g_regex_unref(regex);
    }
    return rc;
}

/* @FIXME uuid.h is an optional header per configure.ac, and we include it
 * conditionally above. But uuid_generate() and uuid_unparse() depend on it, on
 * many or perhaps all systems with libuuid. So it's not clear how it would ever
 * be optional in practice.
 *
 * Note that these functions are not POSIX, although there is probably no good
 * portable alternative.
 *
 * We do list libuuid as a build dependency in INSTALL.md already.
 */

#ifdef HAVE_UUID_UUID_H
#include <uuid/uuid.h>
#endif  // HAVE_UUID_UUID_H

/*!
 * \internal
 * \brief Generate a 37-byte (36 bytes plus null terminator) UUID string
 *
 * \return Newly allocated UUID string
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
char *
pcmk__generate_uuid(void)
{
    uuid_t uuid;

    // uuid_unparse() converts a UUID to a 37-byte string (including null byte)
    char *buffer = pcmk__assert_alloc(37, sizeof(char));

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
 *
 * \note If \p fn returns \c G_SOURCE_CONTINUE, then it will be called again
 *       after \p interval_ms. If \p fn returns \c G_SOURCE_REMOVE, then the
 *       timeout is destroyed and \c fn will not be called again. Note that no
 *       \c GDestroyNotify function is set (see \c g_timeout_add_full() and
 *       \c g_timeout_add_seconds_full()), so only the timeout is destroyed.
 *       \p data is left intact.
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
    pcmk__trace("%s", msg);
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

char *
crm_generate_uuid(void)
{
    return pcmk__generate_uuid();
}

#define PW_BUFFER_LEN 500

int
crm_user_lookup(const char *name, uid_t * uid, gid_t * gid)
{
    int rc = pcmk_ok;
    char *buffer = NULL;
    struct passwd pwd;
    struct passwd *pwentry = NULL;

    buffer = calloc(1, PW_BUFFER_LEN);
    if (buffer == NULL) {
        return -ENOMEM;
    }

    rc = getpwnam_r(name, &pwd, buffer, PW_BUFFER_LEN, &pwentry);
    if (pwentry) {
        if (uid) {
            *uid = pwentry->pw_uid;
        }
        if (gid) {
            *gid = pwentry->pw_gid;
        }
        pcmk__trace("User %s has uid=%d gid=%d", name, pwentry->pw_uid,
                    pwentry->pw_gid);

    } else {
        rc = rc? -rc : -EINVAL;
        pcmk__info("User %s lookup: %s", name, pcmk_strerror(rc));
    }

    free(buffer);
    return rc;
}

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
            pcmk__err("Conversion of '%s' %c failed", text, text[0]);
            atoi_result = -1;
        }
    }
    return atoi_result;
}

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
        pcmk__trace("%s == %s (%d)", version1, version2, lpc);
    } else if (rc < 0) {
        pcmk__trace("%s < %s (%d)", version1, version2, lpc);
    } else if (rc > 0) {
        pcmk__trace("%s > %s (%d)", version1, version2, lpc);
    }

    return rc;
}

// LCOV_EXCL_STOP
// End deprecated API
