/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <inttypes.h>               // PRIu32
#include <stdbool.h>
#include <stdint.h>                 // uint32_t
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <libgen.h>
#include <signal.h>

#include <bzlib.h>
#include <glib.h>                   // g_*, G_*, gboolean, gchar, etc.
#include <qb/qbdefs.h>

#include <crm/crm.h>
#include <crm/common/mainloop.h>

// Use high-resolution (millisecond) timestamps if libqb supports them
#ifdef QB_FEATURE_LOG_HIRES_TIMESTAMPS
#define TIMESTAMP_FORMAT_SPEC "%%T"
typedef struct timespec *log_time_t;
#else
#define TIMESTAMP_FORMAT_SPEC "%%t"
typedef time_t log_time_t;
#endif

unsigned int crm_log_level = LOG_INFO;
unsigned int crm_trace_nonlog = 0;
bool pcmk__is_daemon = false;

static int blackbox_trigger = 0;
static char *blackbox_file_prefix = NULL;

static gchar **trace_blackbox = NULL;
static gchar **trace_files = NULL;
static gchar **trace_formats = NULL;
static gchar **trace_functions = NULL;

static unsigned int crm_log_priority = LOG_NOTICE;
static pcmk__output_t *logger_out = NULL;

pcmk__config_error_func pcmk__config_error_handler = NULL;
pcmk__config_warning_func pcmk__config_warning_handler = NULL;
void *pcmk__config_error_context = NULL;
void *pcmk__config_warning_context = NULL;

static gboolean crm_tracing_enabled(void);

/*!
 * \internal
 * \brief Mapping of a GLib log domain string to its log handler ID
 */
struct log_handler_id {
    //! Log domain
    const char *log_domain;

    /*!
     * Log handler function ID. GLib does not specify the meaning of 0, but
     * based on the implementation, a valid ID is always positive unless we set
     * UINT_MAX handlers.
     */
    guint handler_id;
};

// Log domains that we care about, and their handler function IDs once set
static struct log_handler_id log_handler_ids[] = {
    { G_LOG_DOMAIN, 0 },
    { "GLib", 0 },
    { "GLib-GIO", 0 },
    { "GModule", 0 },
    { "GThread", 0 },
};

/*!
 * \internal
 * \brief Convert a GLib log level to a syslog log level
 *
 * \param[in] log_level  GLib log level
 *
 * \return The syslog level corresponding to \p log_level
 */
static uint8_t
log_level_from_glib(GLogLevelFlags log_level)
{
    switch (log_level & G_LOG_LEVEL_MASK) {
        case G_LOG_LEVEL_CRITICAL:
            return LOG_CRIT;

        case G_LOG_LEVEL_ERROR:
            return LOG_ERR;

        case G_LOG_LEVEL_MESSAGE:
            return LOG_NOTICE;

        case G_LOG_LEVEL_INFO:
            return LOG_INFO;

        case G_LOG_LEVEL_DEBUG:
            return LOG_DEBUG;

        case G_LOG_LEVEL_WARNING:
            return LOG_WARNING;

        default:
            // Default to LOG_NOTICE for any new or custom GLib log levels
            return LOG_NOTICE;
    }
}

/*!
 * \internal
 * \brief Handle a log message from GLib
 *
 * \param[in] log_domain  Log domain of the message
 * \param[in] log_level   Log level of the message (including fatal and
 *                        recursion flags)
 * \param[in] message     Message to process
 * \param[in] user_data   Ignored
 */
static void
handle_glib_message(const gchar *log_domain, GLogLevelFlags log_level,
                    const gchar *message, gpointer user_data)

{
    uint8_t syslog_level = log_level_from_glib(log_level);

    if (syslog_level == LOG_CRIT) {
        static struct qb_log_callsite *glib_cs = NULL;

        if (glib_cs == NULL) {
            glib_cs = qb_log_callsite_get(__func__, __FILE__, "glib-handler",
                                          LOG_DEBUG, __LINE__,
                                          crm_trace_nonlog);
        }

        if (!crm_is_callsite_active(glib_cs, LOG_DEBUG, crm_trace_nonlog)) {
            // Dump core
            crm_abort(__FILE__, __func__, __LINE__, message, true, true);
        }
    }

    do_crm_log(syslog_level, "%s: %s", log_domain, message);
}

/*!
 * \internal
 * \brief Set \c handle_glib_message() as the handler for each GLib log domain
 *
 * The handler will be set for all log levels, including fatal and recursive
 * messages, for each GLib log domain that we care about.
 */
static void
set_glib_log_handlers(void)
{
    for (int i = 0; i < PCMK__NELEM(log_handler_ids); i++) {
        struct log_handler_id *entry = &log_handler_ids[i];

        entry->handler_id = g_log_set_handler(entry->log_domain,
                                              G_LOG_LEVEL_MASK
                                              |G_LOG_FLAG_FATAL
                                              |G_LOG_FLAG_RECURSION,
                                              handle_glib_message, NULL);
    }
}

/*!
 * \internal
 * \brief Remove the handler for each GLib log domain that we care about
 */
static void
remove_glib_log_handlers(void)
{
    for (int i = 0; i < PCMK__NELEM(log_handler_ids); i++) {
        struct log_handler_id *entry = &log_handler_ids[i];

        if (entry->handler_id == 0) {
            continue;
        }

        g_log_remove_handler(entry->log_domain, entry->handler_id);
        entry->handler_id = 0;
    }
}

/*!
 * \internal
 * \brief Set the log format string based on the passed-in method
 *
 * \param[in] method        The detail level of the log output
 * \param[in] daemon        The daemon ID included in error messages
 * \param[in] use_pid       Cached result of getpid() call, for efficiency
 * \param[in] use_nodename  Cached result of uname() call, for efficiency
 */

/* XXX __attribute__((nonnull)) for use_nodename parameter */
static void
set_format_string(int method, const char *daemon, pid_t use_pid,
                  const char *use_nodename)
{
    GString *fmt = NULL;

    if (method == QB_LOG_SYSLOG) {
        // The system log gets a simplified, user-friendly format
        qb_log_ctl(method, QB_LOG_CONF_EXTENDED, QB_FALSE);
        qb_log_format_set(method, "%g %p: %b");
        return;
    }

    // Everything else gets more detail, for advanced troubleshooting
    fmt = g_string_sized_new(256);

    if (method > QB_LOG_STDERR) {
        // If logging to file, prefix with timestamp, node name, daemon ID
        g_string_append_printf(fmt, TIMESTAMP_FORMAT_SPEC " %s %-20s[%lld] ",
                               use_nodename, daemon, (long long) use_pid);
    }

    // Add function name (in parentheses)
    g_string_append(fmt, "(%n");
    if (crm_tracing_enabled()) {
        // When tracing, add file and line number
        g_string_append(fmt, "@%f:%l");
    }
    g_string_append_c(fmt, ')');

    // Add tag (if any), priority, and actual message
    g_string_append(fmt, " %g\t%p: %b");

    qb_log_format_set(method, fmt->str);
    g_string_free(fmt, TRUE);
}

#define DEFAULT_LOG_FILE CRM_LOG_DIR "/pacemaker.log"

static bool
logfile_disabled(const char *filename)
{
    return pcmk__str_eq(filename, PCMK_VALUE_NONE, pcmk__str_casei)
           || pcmk__str_eq(filename, "/dev/null", pcmk__str_none);
}

/*!
 * \internal
 * \brief Fix log file ownership if group is wrong or doesn't have access
 *
 * \param[in] filename  Log file name (for logging only)
 * \param[in] logfd     Log file descriptor
 *
 * \return Standard Pacemaker return code
 */
static int
chown_logfile(const char *filename, int logfd)
{
    uid_t pcmk_uid = 0;
    gid_t pcmk_gid = 0;
    struct stat st;
    int rc = pcmk_rc_ok;

    // Get the log file's current ownership and permissions
    if (fstat(logfd, &st) < 0) {
        return errno;
    }

    // Any other errors don't prevent file from being used as log

    rc = pcmk__daemon_user(&pcmk_uid, &pcmk_gid);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Not changing '%s' ownership because user information "
                   "unavailable: %s",
                   filename, pcmk_rc_str(rc));
        return pcmk_rc_ok;
    }
    if ((st.st_gid == pcmk_gid)
        && ((st.st_mode & S_IRWXG) == (S_IRGRP|S_IWGRP))) {
        return pcmk_rc_ok;
    }
    if (fchown(logfd, pcmk_uid, pcmk_gid) < 0) {
        pcmk__warn("Couldn't change '%s' ownership to user %s gid %d: %s",
                   filename, CRM_DAEMON_USER, pcmk_gid, strerror(errno));
    }
    return pcmk_rc_ok;
}

// Reset log file permissions (using environment variable if set)
static void
chmod_logfile(const char *filename, int logfd)
{
    const char *modestr = pcmk__env_option(PCMK__ENV_LOGFILE_MODE);
    mode_t filemode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

    if (modestr != NULL) {
        long filemode_l = strtol(modestr, NULL, 8);

        if ((filemode_l != LONG_MIN) && (filemode_l != LONG_MAX)) {
            filemode = (mode_t) filemode_l;
        }
    }
    if ((filemode != 0) && (fchmod(logfd, filemode) < 0)) {
        pcmk__warn("Couldn't change '%s' mode to %04o: %s", filename, filemode,
                   strerror(errno));
    }
}

// If we're root, correct a log file's permissions if needed
static int
set_logfile_permissions(const char *filename, FILE *logfile)
{
    if (geteuid() == 0) {
        int logfd = fileno(logfile);
        int rc = chown_logfile(filename, logfd);

        if (rc != pcmk_rc_ok) {
            return rc;
        }
        chmod_logfile(filename, logfd);
    }
    return pcmk_rc_ok;
}

// Enable libqb logging to a new log file
static void
enable_logfile(int fd)
{
    qb_log_ctl(fd, QB_LOG_CONF_ENABLED, QB_TRUE);
#if 0
    qb_log_ctl(fd, QB_LOG_CONF_FILE_SYNC, 1); // Turn on synchronous writes
#endif

#ifdef HAVE_qb_log_conf_QB_LOG_CONF_MAX_LINE_LEN
    // Longer than default, for logging long XML lines
    qb_log_ctl(fd, QB_LOG_CONF_MAX_LINE_LEN, 800);
#endif

    crm_update_callsites();
}

static inline void
disable_logfile(int fd)
{
    qb_log_ctl(fd, QB_LOG_CONF_ENABLED, QB_FALSE);
}

static void
setenv_logfile(const char *filename)
{
    // Some resource agents will log only if environment variable is set
    if (pcmk__env_option(PCMK__ENV_LOGFILE) == NULL) {
        pcmk__set_env_option(PCMK__ENV_LOGFILE, filename, true);
    }
}

/*!
 * \brief Add a file to be used as a Pacemaker detail log
 *
 * \param[in] filename  Name of log file to use
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__add_logfile(const char *filename)
{
    /* No log messages from this function will be logged to the new log!
     * If another target such as syslog has already been added, the messages
     * should show up there.
     */

    int fd = 0;
    int rc = pcmk_rc_ok;
    FILE *logfile = NULL;
    bool is_default = false;

    static int default_fd = -1;
    static bool have_logfile = false;

    // Use default if caller didn't specify (and we don't already have one)
    if (filename == NULL) {
        if (have_logfile) {
            return pcmk_rc_ok;
        }
        filename = DEFAULT_LOG_FILE;
    }

    // If the user doesn't want logging, we're done
    if (logfile_disabled(filename)) {
        return pcmk_rc_ok;
    }

    // If the caller wants the default and we already have it, we're done
    is_default = pcmk__str_eq(filename, DEFAULT_LOG_FILE, pcmk__str_none);
    if (is_default && (default_fd >= 0)) {
        return pcmk_rc_ok;
    }

    // Check whether we have write access to the file
    logfile = fopen(filename, "a");
    if (logfile == NULL) {
        rc = errno;
        pcmk__warn("Logging to '%s' is disabled: %s " QB_XS " uid=%u gid=%u",
                   filename, strerror(rc), geteuid(), getegid());
        return rc;
    }

    rc = set_logfile_permissions(filename, logfile);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Logging to '%s' is disabled: %s " QB_XS " permissions",
                   filename, strerror(rc));
        fclose(logfile);
        return rc;
    }

    // Close and reopen as libqb logging target
    fclose(logfile);
    fd = qb_log_file_open(filename);
    if (fd < 0) {
        pcmk__warn("Logging to '%s' is disabled: %s " QB_XS " qb_log_file_open",
                   filename, strerror(-fd));
        return -fd; // == +errno
    }

    if (is_default) {
        default_fd = fd;
        setenv_logfile(filename);

    } else if (default_fd >= 0) {
        pcmk__notice("Switching logging to %s", filename);
        disable_logfile(default_fd);
    }

    pcmk__notice("Additional logging available in %s", filename);
    enable_logfile(fd);
    have_logfile = true;
    return pcmk_rc_ok;
}

/*!
 * \brief Add multiple additional log files
 *
 * \param[in] log_files  Array of log files to add
 * \param[in] out        Output object to use for error reporting
 *
 * \return Standard Pacemaker return code
 */
void
pcmk__add_logfiles(gchar **log_files, pcmk__output_t *out)
{
    if (log_files == NULL) {
        return;
    }

    for (gchar **fname = log_files; *fname != NULL; fname++) {
        int rc = pcmk__add_logfile(*fname);

        if (rc != pcmk_rc_ok) {
            out->err(out, "Logging to %s is disabled: %s",
                     *fname, pcmk_rc_str(rc));
        }
    }
}

/*!
 * \internal
 * \brief Write out a blackbox (enabling blackboxes if the signal is \c SIGTRAP)
 *
 * \param[in] nsig  Signal number that was received
 *
 * \note This is a true signal handler, and so must be async-safe.
 */
static void
enable_and_write_blackbox(int nsig)
{
    if (nsig == SIGTRAP) {
        crm_enable_blackbox(nsig);
    }

    crm_write_blackbox(nsig, NULL);
}

static void
blackbox_logger(int32_t t, struct qb_log_callsite *cs, log_time_t timestamp,
                const char *msg)
{
    if(cs && cs->priority < LOG_ERR) {
        crm_write_blackbox(SIGTRAP, cs); /* Bypass the over-dumping logic */
    } else {
        crm_write_blackbox(0, cs);
    }
}

void
crm_enable_blackbox(int nsig)
{
    if (qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_STATE_GET,
                   0) == QB_LOG_STATE_ENABLED) {
        return;
    }

    // Any size change drops existing entries
    qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_SIZE, 5 * 1024 * 1024);

    // Setting the size seems to disable the log target
    qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_TRUE);

    /* Enable synchronous logging for each target except QB_LOG_SYSLOG and
     * QB_LOG_STDERR
     */
    for (int i = QB_LOG_BLACKBOX; i < QB_LOG_TARGET_MAX; i++) {
        qb_log_ctl(i, QB_LOG_CONF_FILE_SYNC, QB_TRUE);
    }

    pcmk__notice("Initiated blackbox recorder: %s", blackbox_file_prefix);

    // Save to disk on abnormal termination
    crm_signal_handler(SIGSEGV, enable_and_write_blackbox);
    crm_signal_handler(SIGABRT, enable_and_write_blackbox);
    crm_signal_handler(SIGILL, enable_and_write_blackbox);
    crm_signal_handler(SIGBUS, enable_and_write_blackbox);
    crm_signal_handler(SIGFPE, enable_and_write_blackbox);

    crm_update_callsites();

    blackbox_trigger = qb_log_custom_open(blackbox_logger, NULL, NULL, NULL);
    qb_log_ctl(blackbox_trigger, QB_LOG_CONF_ENABLED, QB_TRUE);
    pcmk__trace("Trigger: %d is %d %d", blackbox_trigger,
                qb_log_ctl(blackbox_trigger, QB_LOG_CONF_STATE_GET, 0),
                QB_LOG_STATE_ENABLED);

    crm_update_callsites();
}

void
crm_disable_blackbox(int nsig)
{
    if (qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_STATE_GET,
                   0) != QB_LOG_STATE_ENABLED) {
        return;
    }

    qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_FALSE);

    // Disable synchronous logging again when the blackbox is disabled
    for (int i = QB_LOG_BLACKBOX; i < QB_LOG_TARGET_MAX; i++) {
        qb_log_ctl(i, QB_LOG_CONF_FILE_SYNC, QB_FALSE);
    }
}

/*!
 * \internal
 * \brief Write out a blackbox, if blackboxes are enabled
 *
 * \param[in] nsig  Signal that was received
 * \param[in] cs    libqb callsite
 *
 * \note This may be called via a true signal handler and so must be async-safe.
 * @TODO actually make this async-safe
 */
void
crm_write_blackbox(int nsig, const struct qb_log_callsite *cs)
{
    static volatile int counter = 1;
    static volatile time_t last = 0;

    char *buffer = NULL;
    int rc = 0;
    time_t now = time(NULL);

    if (blackbox_file_prefix == NULL) {
        return;
    }

    switch (nsig) {
        case 0:
        case SIGTRAP:
            /* The graceful case - such as assertion failure or user request */

            if (nsig == 0 && now == last) {
                /* Prevent over-dumping */
                return;
            }

            buffer = pcmk__assert_asprintf("%s.%d", blackbox_file_prefix,
                                           counter++);
            if (nsig == SIGTRAP) {
                pcmk__notice("Blackbox dump requested, please see %s for "
                             "contents",
                             buffer);

            } else if (cs) {
                syslog(LOG_NOTICE,
                       "Problem detected at %s:%d (%s), please see %s for additional details",
                       cs->function, cs->lineno, cs->filename, buffer);
            } else {
                pcmk__notice("Problem detected, please see %s for additional "
                             "details",
                             buffer);
            }

            last = now;

            rc = qb_log_blackbox_write_to_file(buffer);
            if (rc < 0) {
                // System errno
                pcmk__err("Failed to write blackbox file %s: %s", buffer,
                          strerror(-rc));
            }

            /* Flush the existing contents
             * A size change would also work
             */
            qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_FALSE);
            qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_TRUE);
            break;

        default:
            /* Do as little as possible, just try to get what we have out
             * We logged the filename when the blackbox was enabled
             */
            crm_signal_handler(nsig, SIG_DFL);
            qb_log_blackbox_write_to_file((const char *)blackbox_file_prefix);
            qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_FALSE);
            raise(nsig);
            break;
    }

    free(buffer);
}

static const char *
crm_quark_to_string(uint32_t tag)
{
    const char *text = g_quark_to_string(tag);

    if (text) {
        return text;
    }
    return "";
}

static void
crm_log_filter_source(int source, struct qb_log_callsite *cs)
{
    if (qb_log_ctl(source, QB_LOG_CONF_STATE_GET, 0) != QB_LOG_STATE_ENABLED) {
        return;
    }

    if ((cs->tags != crm_trace_nonlog) && (source == QB_LOG_BLACKBOX)) {
        /* Blackbox gets everything if enabled */
        qb_bit_set(cs->targets, source);
        return;
    }

    if ((source == blackbox_trigger) && (blackbox_trigger > 0)) {
        /* Should this log message result in the blackbox being dumped */
        if (cs->priority <= LOG_ERR) {
            qb_bit_set(cs->targets, source);

        } else if (trace_blackbox != NULL) {
            char *key = pcmk__assert_asprintf("%s:%d", cs->function,
                                              cs->lineno);

            if (pcmk__g_strv_contains(trace_blackbox, key)) {
                qb_bit_set(cs->targets, source);
            }
            free(key);
        }
        return;
    }

    if (source == QB_LOG_SYSLOG) {
        // No tracing to syslog
        if ((cs->priority <= crm_log_priority)
            && (cs->priority <= crm_log_level)) {

            qb_bit_set(cs->targets, source);
        }
        return;
    }

    if (cs->priority <= crm_log_level) {
        qb_bit_set(cs->targets, source);
        return;
    }

    if ((trace_files != NULL)
        && pcmk__g_strv_contains(trace_files, cs->filename)) {

        qb_bit_set(cs->targets, source);
        return;
    }

    if ((trace_functions != NULL)
        && pcmk__g_strv_contains(trace_functions, cs->function)) {

        qb_bit_set(cs->targets, source);
        return;
    }

    if ((trace_formats != NULL)
        && pcmk__g_strv_contains(trace_formats, cs->format)) {

        qb_bit_set(cs->targets, source);
        return;
    }

    if ((cs->tags != 0) && (cs->tags != crm_trace_nonlog)
        && (g_quark_to_string(cs->tags) != NULL)) {

        qb_bit_set(cs->targets, source);
    }
}

static void
crm_log_filter(struct qb_log_callsite *cs)
{
    cs->targets = 0;            /* Reset then find targets to enable */
    for (int i = QB_LOG_SYSLOG; i < QB_LOG_TARGET_MAX; i++) {
        crm_log_filter_source(i, cs);
    }
}

/*!
 * \internal
 * \brief Parse environment variables specifying which objects to trace
 */
static void
init_tracing(void)
{
    const char *blackbox = pcmk__env_option(PCMK__ENV_TRACE_BLACKBOX);
    const char *files = pcmk__env_option(PCMK__ENV_TRACE_FILES);
    const char *formats = pcmk__env_option(PCMK__ENV_TRACE_FORMATS);
    const char *functions = pcmk__env_option(PCMK__ENV_TRACE_FUNCTIONS);
    const char *tags = pcmk__env_option(PCMK__ENV_TRACE_TAGS);

    if (blackbox != NULL) {
        trace_blackbox = g_strsplit(blackbox, ",", 0);
    }

    if (files != NULL) {
        trace_files = g_strsplit(files, ",", 0);
    }

    if (formats != NULL) {
        trace_formats = g_strsplit(formats, ",", 0);
    }

    if (functions != NULL) {
        trace_functions = g_strsplit(functions, ",", 0);
    }

    if (tags != NULL) {
        gchar **trace_tags = g_strsplit(tags, ",", 0);

        for (gchar **tag = trace_tags; *tag != NULL; tag++) {
            if (pcmk__str_empty(*tag)) {
                continue;
            }

            pcmk__info("Created GQuark %lld from token '%s' in '%s'",
                       (long long) g_quark_from_string(*tag), *tag, tags);
        }

        // We have the GQuarks, so we don't need the array anymore
        g_strfreev(trace_tags);
    }
}

/*!
 * \internal
 * \brief Free arrays of parsed trace objects
 */
static void
cleanup_tracing(void)
{
    g_clear_pointer(&trace_blackbox, g_strfreev);
    g_clear_pointer(&trace_files, g_strfreev);
    g_clear_pointer(&trace_formats, g_strfreev);
    g_clear_pointer(&trace_functions, g_strfreev);
}

gboolean
crm_is_callsite_active(struct qb_log_callsite *cs, uint8_t level, uint32_t tags)
{
    gboolean refilter = FALSE;

    if (cs == NULL) {
        return FALSE;
    }

    if (cs->priority != level) {
        cs->priority = level;
        refilter = TRUE;
    }

    if (cs->tags != tags) {
        cs->tags = tags;
        refilter = TRUE;
    }

    if (refilter) {
        crm_log_filter(cs);
    }

    if (cs->targets == 0) {
        return FALSE;
    }
    return TRUE;
}

void
crm_update_callsites(void)
{
    static bool log = true;

    if (log) {
        log = false;
        pcmk__debug("Enabling callsites based on priority=%d, files=%s, "
                    "functions=%s, formats=%s, tags=%s",
                    crm_log_level,
                    pcmk__s(pcmk__env_option(PCMK__ENV_TRACE_FILES), "<null>"),
                    pcmk__s(pcmk__env_option(PCMK__ENV_TRACE_FUNCTIONS),
                            "<null>"),
                    pcmk__s(pcmk__env_option(PCMK__ENV_TRACE_FORMATS),
                            "<null>"),
                    pcmk__s(pcmk__env_option(PCMK__ENV_TRACE_TAGS), "<null>"));
    }
    qb_log_filter_fn_set(crm_log_filter);
}

static gboolean
crm_tracing_enabled(void)
{
    return (crm_log_level == LOG_TRACE)
            || (pcmk__env_option(PCMK__ENV_TRACE_FILES) != NULL)
            || (pcmk__env_option(PCMK__ENV_TRACE_FUNCTIONS) != NULL)
            || (pcmk__env_option(PCMK__ENV_TRACE_FORMATS) != NULL)
            || (pcmk__env_option(PCMK__ENV_TRACE_TAGS) != NULL);
}

static int
crm_priority2int(const char *name)
{
    struct syslog_names {
        const char *name;
        int priority;
    };
    static struct syslog_names p_names[] = {
        {"emerg", LOG_EMERG},
        {"alert", LOG_ALERT},
        {"crit", LOG_CRIT},
        {"error", LOG_ERR},
        {"warning", LOG_WARNING},
        {"notice", LOG_NOTICE},
        {"info", LOG_INFO},
        {"debug", LOG_DEBUG},
        {NULL, -1}
    };

    for (int i = 0; (name != NULL) && (p_names[i].name != NULL); i++) {
        if (pcmk__str_eq(p_names[i].name, name, pcmk__str_none)) {
            return p_names[i].priority;
        }
    }
    return crm_log_priority;
}


/*!
 * \internal
 * \brief Set the identifier for the current process
 *
 * If the identifier crm_system_name is not already set, then it is set as follows:
 * - it is passed to the function via the "entity" parameter, or
 * - it is derived from the executable name
 *
 * The identifier can be used in logs, IPC, and more.
 *
 * This method also sets the PCMK_service environment variable.
 *
 * \param[in] entity  If not NULL, will be assigned to the identifier
 * \param[in] argc    The number of command line parameters
 * \param[in] argv    The command line parameter values
 */
static void
set_identity(const char *entity, int argc, char *const *argv)
{
    if (crm_system_name != NULL) {
        return; // Already set, don't overwrite
    }

    if (entity != NULL) {
        crm_system_name = pcmk__str_copy(entity);

    } else if ((argc > 0) && (argv != NULL)) {
        char *mutable = strdup(argv[0]);
        char *modified = basename(mutable);

        if (strstr(modified, "lt-") == modified) {
            modified += 3;
        }
        crm_system_name = pcmk__str_copy(modified);
        free(mutable);

    } else {
        crm_system_name = pcmk__str_copy("Unknown");
    }

    // Used by fencing.py.py (in fence-agents)
    pcmk__set_env_option(PCMK__ENV_SERVICE, crm_system_name, false);
}

void
crm_log_preinit(const char *entity, int argc, char *const *argv)
{
    /* Configure libqb logging with nothing turned on */
    static bool have_logging = false;
    struct utsname res = { 0, };
    const pid_t pid = getpid();
    const char *nodename = "localhost";

    if (have_logging) {
        return;
    }

    have_logging = true;

    init_tracing();

    /* @TODO Try to create a more obvious "global Pacemaker initializer"
     * function than crm_log_preinit(), and call pcmk__schema_init() there.
     * See also https://projects.clusterlabs.org/T840.
     */
    pcmk__schema_init();

    if (crm_trace_nonlog == 0) {
        crm_trace_nonlog = g_quark_from_static_string("Pacemaker non-logging tracepoint");
    }

    umask(S_IWGRP | S_IWOTH | S_IROTH);

    set_glib_log_handlers();

    /* glib should not abort for any messages from the Pacemaker domain, but
     * other domains are still free to specify their own behavior.  However,
     * note that G_LOG_LEVEL_ERROR is always fatal regardless of what we do
     * here.
     */
    g_log_set_fatal_mask(G_LOG_DOMAIN, 0);

    /* Set crm_system_name, which is used as the logging name. It may also
     * be used for other purposes such as an IPC client name.
     */
    set_identity(entity, argc, argv);

    qb_log_init(crm_system_name, qb_log_facility2int("local0"), LOG_ERR);
    crm_log_level = LOG_CRIT;

    /* Nuke any syslog activity until it's asked for */
    qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_FALSE);
#ifdef HAVE_qb_log_conf_QB_LOG_CONF_MAX_LINE_LEN
    // Shorter than default, generous for what we *should* send to syslog
    qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_MAX_LINE_LEN, 256);
#endif

    if ((uname(&res) == 0) && !pcmk__str_empty(res.nodename)) {
        nodename = res.nodename;
    }

    /* Set format strings and disable threading
     * Pacemaker and threads do not mix well (due to the amount of forking)
     */
    qb_log_tags_stringify_fn_set(crm_quark_to_string);
    for (int i = QB_LOG_SYSLOG; i < QB_LOG_TARGET_MAX; i++) {
        qb_log_ctl(i, QB_LOG_CONF_THREADED, QB_FALSE);
#ifdef HAVE_qb_log_conf_QB_LOG_CONF_ELLIPSIS
        // End truncated lines with '...'
        qb_log_ctl(i, QB_LOG_CONF_ELLIPSIS, QB_TRUE);
#endif
        set_format_string(i, crm_system_name, pid, nodename);
    }

#ifdef ENABLE_NLS
    /* Enable translations (experimental). Currently we only have a few
     * proof-of-concept translations for some option help. The goal would be to
     * offer translations for option help and man pages rather than logs or
     * documentation, to reduce the burden of maintaining them.
     */

    // Load locale information for the local host from the environment
    setlocale(LC_ALL, "");

    // Tell gettext where to find Pacemaker message catalogs
    pcmk__assert(bindtextdomain(PACKAGE, PCMK__LOCALE_DIR) != NULL);

    // Tell gettext to use the Pacemaker message catalogs
    pcmk__assert(textdomain(PACKAGE) != NULL);

    // Tell gettext that the translated strings are stored in UTF-8
    bind_textdomain_codeset(PACKAGE, "UTF-8");
#endif
}

gboolean
crm_log_init(const char *entity, uint8_t level, gboolean daemon, gboolean to_stderr,
             int argc, char **argv, gboolean quiet)
{
    const char *syslog_priority = NULL;
    const char *facility = pcmk__env_option(PCMK__ENV_LOGFACILITY);
    const char *f_copy = facility;

    pcmk__is_daemon = daemon;
    crm_log_preinit(entity, argc, argv);

    if (level > LOG_TRACE) {
        level = LOG_TRACE;
    }
    if(level > crm_log_level) {
        crm_log_level = level;
    }

    /* Should we log to syslog */
    if (facility == NULL) {
        if (pcmk__is_daemon) {
            facility = "daemon";
        } else {
            facility = PCMK_VALUE_NONE;
        }
        pcmk__set_env_option(PCMK__ENV_LOGFACILITY, facility, true);
    }

    if (pcmk__str_eq(facility, PCMK_VALUE_NONE, pcmk__str_casei)) {
        quiet = TRUE;


    } else {
        qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_FACILITY, qb_log_facility2int(facility));
    }

    if (pcmk__env_option_enabled(crm_system_name, PCMK__ENV_DEBUG)) {
        /* Override the default setting */
        crm_log_level = LOG_DEBUG;
    }

    /* What lower threshold do we have for sending to syslog */
    syslog_priority = pcmk__env_option(PCMK__ENV_LOGPRIORITY);
    if (syslog_priority) {
        crm_log_priority = crm_priority2int(syslog_priority);
    }
    qb_log_filter_ctl(QB_LOG_SYSLOG, QB_LOG_FILTER_ADD, QB_LOG_FILTER_FILE, "*",
                      crm_log_priority);

    // Log to syslog unless requested to be quiet
    if (!quiet) {
        qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_TRUE);
    }

    /* Should we log to stderr */ 
    if (pcmk__env_option_enabled(crm_system_name, PCMK__ENV_STDERR)) {
        /* Override the default setting */
        to_stderr = TRUE;
    }
    crm_enable_stderr(to_stderr);

    // Log to a file if we're a daemon or user asked for one
    {
        const char *logfile = pcmk__env_option(PCMK__ENV_LOGFILE);

        if (!pcmk__str_eq(PCMK_VALUE_NONE, logfile, pcmk__str_casei)
            && (pcmk__is_daemon || (logfile != NULL))) {
            // Daemons always get a log file, unless explicitly set to "none"
            pcmk__add_logfile(logfile);
        }
    }

    if (pcmk__is_daemon
        && pcmk__env_option_enabled(crm_system_name, PCMK__ENV_BLACKBOX)) {
        crm_enable_blackbox(0);
    }

    /* Summary */
    pcmk__trace("Quiet: %d, facility %s", quiet, f_copy);
    pcmk__env_option(PCMK__ENV_LOGFILE);
    pcmk__env_option(PCMK__ENV_LOGFACILITY);

    crm_update_callsites();

    /* Ok, now we can start logging... */

    // Disable daemon request if user isn't root or Pacemaker daemon user
    if (pcmk__is_daemon) {
        const char *user = getenv("USER");

        if (user != NULL && !pcmk__strcase_any_of(user, "root", CRM_DAEMON_USER, NULL)) {
            pcmk__trace("Not switching to corefile directory for %s", user);
            pcmk__is_daemon = false;
        }
    }

    if (pcmk__is_daemon) {
        char *user = pcmk__uid2username(getuid());

        if (user == NULL) {
            // Error already logged

        } else if (!pcmk__str_any_of(user, "root", CRM_DAEMON_USER, NULL)) {
            pcmk__trace("Don't change active directory for regular user %s",
                        user);

        } else if (chdir(CRM_CORE_DIR) < 0) {
            pcmk__info("Cannot change active directory to " CRM_CORE_DIR ": %s",
                       strerror(errno));

        } else {
            pcmk__info("Changed active directory to " CRM_CORE_DIR);
        }

        blackbox_file_prefix = pcmk__assert_asprintf(CRM_BLACKBOX_DIR
                                                     "/%s-%lld",
                                                     crm_system_name,
                                                     (long long) getpid());
        /* Original meanings from signal(7)
         *
         * Signal       Value     Action   Comment
         * SIGTRAP        5        Core    Trace/breakpoint trap
         * SIGUSR1     30,10,16    Term    User-defined signal 1
         * SIGUSR2     31,12,17    Term    User-defined signal 2
         *
         * Our usage is as similar as possible
         */
        mainloop_add_signal(SIGUSR1, crm_enable_blackbox);
        mainloop_add_signal(SIGUSR2, crm_disable_blackbox);
        mainloop_add_signal(SIGTRAP, enable_and_write_blackbox);

        free(user);

    } else if (!quiet) {
        crm_log_args(argc, argv);
    }

    return TRUE;
}

/*!
 * \internal
 * \brief Free the logging library's internal data structures
 */
void
crm_log_deinit(void)
{
    remove_glib_log_handlers();
    cleanup_tracing();

    if (logger_out != NULL) {
        logger_out->finish(logger_out, CRM_EX_OK, true, NULL);
        g_clear_pointer(&logger_out, pcmk__output_free);
    }

    g_clear_pointer(&blackbox_file_prefix, free);
    g_clear_pointer(&crm_system_name, free);
}

/* returns the old value */
unsigned int
set_crm_log_level(unsigned int level)
{
    unsigned int old = crm_log_level;

    if (level > LOG_TRACE) {
        level = LOG_TRACE;
    }
    crm_log_level = level;
    crm_update_callsites();
    pcmk__trace("New log level: %d", level);
    return old;
}

void
crm_enable_stderr(int enable)
{
    if (enable && qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_STATE_GET, 0) != QB_LOG_STATE_ENABLED) {
        qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_ENABLED, QB_TRUE);
        crm_update_callsites();

    } else if (enable == FALSE) {
        qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_ENABLED, QB_FALSE);
    }
}

/*!
 * \brief Make logging more verbose
 *
 * If logging to stderr is not already enabled when this function is called,
 * enable it. Otherwise, increase the log level by 1.
 *
 * \param[in] argc  Ignored
 * \param[in] argv  Ignored
 */
void
crm_bump_log_level(int argc, char **argv)
{
    if (qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_STATE_GET, 0)
        != QB_LOG_STATE_ENABLED) {
        crm_enable_stderr(TRUE);
    } else {
        set_crm_log_level(crm_log_level + 1);
    }
}

unsigned int
get_crm_log_level(void)
{
    return crm_log_level;
}

/*!
 * \brief Log the command line (once)
 *
 * \param[in]  Number of values in \p argv
 * \param[in]  Command-line arguments (including command name)
 *
 * \note This function will only log once, even if called with different
 *       arguments.
 */
void
crm_log_args(int argc, char **argv)
{
    static bool logged = false;
    gchar *arg_string = NULL;

    if ((argc == 0) || (argv == NULL) || logged) {
        return;
    }
    logged = true;
    arg_string = g_strjoinv(" ", argv);
    pcmk__notice("Invoked: %s", arg_string);
    g_free(arg_string);
}

void
crm_log_output_fn(const char *file, const char *function, int line, int level, const char *prefix,
                  const char *output)
{
    gchar **out_lines = NULL;

    if (level == PCMK__LOG_NEVER) {
        return;
    }

    if (output == NULL) {
        if (level != PCMK__LOG_STDOUT) {
            level = LOG_TRACE;
        }
        output = "-- empty --";
    }

    out_lines = g_strsplit(output, "\n", 0);

    for (gchar **out_line = out_lines; *out_line != NULL; out_line++) {
        do_crm_log_alias(level, file, function, line, "%s [ %s ]",
                         prefix, *out_line);
    }

    g_strfreev(out_lines);
}

void
pcmk__cli_init_logging(const char *name, unsigned int verbosity)
{
    crm_log_init(name, LOG_ERR, FALSE, FALSE, 0, NULL, TRUE);

    for (int i = 0; i < verbosity; i++) {
        /* These arguments are ignored, so pass placeholders. */
        crm_bump_log_level(0, NULL);
    }
}

/*!
 * \brief Log XML line-by-line in a formatted fashion
 *
 * \param[in] file      File name to use for log filtering
 * \param[in] function  Function name to use for log filtering
 * \param[in] line      Line number to use for log filtering
 * \param[in] tags      Logging tags to use for log filtering
 * \param[in] level     Priority at which to log the messages
 * \param[in] text      Prefix for each line
 * \param[in] xml       XML to log
 *
 * \note This does nothing when \p level is \c PCMK__LOG_STDOUT.
 * \note Do not call this function directly. It should be called only from the
 *       \p do_crm_log_xml() macro.
 */
void
pcmk_log_xml_as(const char *file, const char *function, uint32_t line,
                uint32_t tags, uint8_t level, const char *text, const xmlNode *xml)
{
    if (xml == NULL) {
        do_crm_log(level, "%s%sNo data to dump as XML",
                   pcmk__s(text, ""), pcmk__str_empty(text)? "" : " ");

    } else {
        if (logger_out == NULL) {
            CRM_CHECK(pcmk__log_output_new(&logger_out) == pcmk_rc_ok, return);
        }

        pcmk__output_set_log_level(logger_out, level);
        pcmk__output_set_log_filter(logger_out, file, function, line, tags);
        pcmk__xml_show(logger_out, text, xml, 1,
                       pcmk__xml_fmt_pretty
                       |pcmk__xml_fmt_open
                       |pcmk__xml_fmt_children
                       |pcmk__xml_fmt_close);
        pcmk__output_set_log_filter(logger_out, NULL, NULL, 0U, 0U);
    }
}

/*!
 * \internal
 * \brief Log XML changes line-by-line in a formatted fashion
 *
 * \param[in] file      File name to use for log filtering
 * \param[in] function  Function name to use for log filtering
 * \param[in] line      Line number to use for log filtering
 * \param[in] tags      Logging tags to use for log filtering
 * \param[in] level     Priority at which to log the messages
 * \param[in] xml       XML whose changes to log
 *
 * \note This does nothing when \p level is \c PCMK__LOG_STDOUT.
 */
void
pcmk__log_xml_changes_as(const char *file, const char *function, uint32_t line,
                         uint32_t tags, uint8_t level, const xmlNode *xml)
{
    if (xml == NULL) {
        do_crm_log(level, "No XML to dump");
        return;
    }

    if (logger_out == NULL) {
        CRM_CHECK(pcmk__log_output_new(&logger_out) == pcmk_rc_ok, return);
    }
    pcmk__output_set_log_level(logger_out, level);
    pcmk__output_set_log_filter(logger_out, file, function, line, tags);
    pcmk__xml_show_changes(logger_out, xml);
    pcmk__output_set_log_filter(logger_out, NULL, NULL, 0U, 0U);
}

/*!
 * \internal
 * \brief Log an XML patchset line-by-line in a formatted fashion
 *
 * \param[in] file      File name to use for log filtering
 * \param[in] function  Function name to use for log filtering
 * \param[in] line      Line number to use for log filtering
 * \param[in] tags      Logging tags to use for log filtering
 * \param[in] level     Priority at which to log the messages
 * \param[in] patchset  XML patchset to log
 *
 * \note This does nothing when \p level is \c PCMK__LOG_STDOUT.
 */
void
pcmk__log_xml_patchset_as(const char *file, const char *function, uint32_t line,
                          uint32_t tags, uint8_t level, const xmlNode *patchset)
{
    if (patchset == NULL) {
        do_crm_log(level, "No patchset to dump");
        return;
    }

    if (logger_out == NULL) {
        CRM_CHECK(pcmk__log_output_new(&logger_out) == pcmk_rc_ok, return);
    }
    pcmk__output_set_log_level(logger_out, level);
    pcmk__output_set_log_filter(logger_out, file, function, line, tags);
    logger_out->message(logger_out, "xml-patchset", patchset);
    pcmk__output_set_log_filter(logger_out, NULL, NULL, 0U, 0U);
}

void pcmk__set_config_error_handler(pcmk__config_error_func error_handler, void *error_context)
{
    pcmk__config_error_handler = error_handler;
    pcmk__config_error_context = error_context;    
}

void pcmk__set_config_warning_handler(pcmk__config_warning_func warning_handler, void *warning_context)
{
    pcmk__config_warning_handler = warning_handler;
    pcmk__config_warning_context = warning_context;   
}
