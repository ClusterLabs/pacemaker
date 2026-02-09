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

static unsigned int crm_log_priority = LOG_NOTICE;
static guint pcmk__log_id = 0;
static guint pcmk__glib_log_id = 0;
static guint pcmk__gio_log_id = 0;
static guint pcmk__gmodule_log_id = 0;
static guint pcmk__gthread_log_id = 0;
static pcmk__output_t *logger_out = NULL;

pcmk__config_error_func pcmk__config_error_handler = NULL;
pcmk__config_warning_func pcmk__config_warning_handler = NULL;
void *pcmk__config_error_context = NULL;
void *pcmk__config_warning_context = NULL;

static gboolean crm_tracing_enabled(void);

static void
crm_glib_handler(const gchar * log_domain, GLogLevelFlags flags, const gchar * message,
                 gpointer user_data)
{
    int log_level = LOG_WARNING;
    static struct qb_log_callsite *glib_cs = NULL;

    if (glib_cs == NULL) {
        glib_cs = qb_log_callsite_get(__func__, __FILE__, "glib-handler",
                                      LOG_DEBUG, __LINE__, crm_trace_nonlog);
    }

    switch (flags & G_LOG_LEVEL_MASK) {
        case G_LOG_LEVEL_CRITICAL:
            log_level = LOG_CRIT;

            if (!crm_is_callsite_active(glib_cs, LOG_DEBUG, crm_trace_nonlog)) {
                /* log and record how we got here */
                crm_abort(__FILE__, __func__, __LINE__, message, TRUE, TRUE);
            }
            break;

        case G_LOG_LEVEL_ERROR:
            log_level = LOG_ERR;
            break;
        case G_LOG_LEVEL_MESSAGE:
            log_level = LOG_NOTICE;
            break;
        case G_LOG_LEVEL_INFO:
            log_level = LOG_INFO;
            break;
        case G_LOG_LEVEL_DEBUG:
            log_level = LOG_DEBUG;
            break;
        case G_LOG_LEVEL_WARNING:
            log_level = LOG_WARNING;
            break;
        default:
            /* Default to NOTICE for any new or custom glib log levels */
            log_level = LOG_NOTICE;
            break;
    }

    do_crm_log(log_level, "%s: %s", log_domain, message);
}

#ifndef NAME_MAX
#  define NAME_MAX 256
#endif

/*!
 * \internal
 * \brief Write out a blackbox (enabling blackboxes if needed)
 *
 * \param[in] nsig  Signal number that was received
 *
 * \note This is a true signal handler, and so must be async-safe.
 */
static void
crm_trigger_blackbox(int nsig)
{
    if(nsig == SIGTRAP) {
        /* Turn it on if it wasn't already */
        crm_enable_blackbox(nsig);
    }
    crm_write_blackbox(nsig, NULL);
}

void
crm_log_deinit(void)
{
    if (pcmk__log_id == 0) {
        return;
    }

    g_log_remove_handler(G_LOG_DOMAIN, pcmk__log_id);
    pcmk__log_id = 0;
    g_log_remove_handler("GLib", pcmk__glib_log_id);
    pcmk__glib_log_id = 0;
    g_log_remove_handler("GLib-GIO", pcmk__gio_log_id);
    pcmk__gio_log_id = 0;
    g_log_remove_handler("GModule", pcmk__gmodule_log_id);
    pcmk__gmodule_log_id = 0;
    g_log_remove_handler("GThread", pcmk__gthread_log_id);
    pcmk__gthread_log_id = 0;
}

#define FMT_MAX 256

/*!
 * \internal
 * \brief Set the log format string based on the passed-in method
 *
 * \param[in] method        The detail level of the log output
 * \param[in] daemon        The daemon ID included in error messages
 * \param[in] use_pid       Cached result of getpid() call, for efficiency
 * \param[in] use_nodename  Cached result of uname() call, for efficiency
 *
 */

/* XXX __attribute__((nonnull)) for use_nodename parameter */
static void
set_format_string(int method, const char *daemon, pid_t use_pid,
                  const char *use_nodename)
{
    if (method == QB_LOG_SYSLOG) {
        // The system log gets a simplified, user-friendly format
        qb_log_ctl(method, QB_LOG_CONF_EXTENDED, QB_FALSE);
        qb_log_format_set(method, "%g %p: %b");

    } else {
        // Everything else gets more detail, for advanced troubleshooting

        int offset = 0;
        char fmt[FMT_MAX];

        if (method > QB_LOG_STDERR) {
            // If logging to file, prefix with timestamp, node name, daemon ID
            offset += snprintf(fmt + offset, FMT_MAX - offset,
                               TIMESTAMP_FORMAT_SPEC " %s %-20s[%lu] ",
                                use_nodename, daemon, (unsigned long) use_pid);
        }

        // Add function name (in parentheses)
        offset += snprintf(fmt + offset, FMT_MAX - offset, "(%%n");
        if (crm_tracing_enabled()) {
            // When tracing, add file and line number
            offset += snprintf(fmt + offset, FMT_MAX - offset, "@%%f:%%l");
        }
        offset += snprintf(fmt + offset, FMT_MAX - offset, ")");

        // Add tag (if any), severity, and actual message
        offset += snprintf(fmt + offset, FMT_MAX - offset, " %%g\t%%p: %%b");

        CRM_LOG_ASSERT(offset > 0);
        qb_log_format_set(method, fmt);
    }
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
    int rc;

    // Get the log file's current ownership and permissions
    if (fstat(logfd, &st) < 0) {
        return errno;
    }

    // Any other errors don't prevent file from being used as log

    rc = pcmk_daemon_user(&pcmk_uid, &pcmk_gid);
    if (rc != pcmk_ok) {
        rc = pcmk_legacy2rc(rc);
        crm_warn("Not changing '%s' ownership because user information "
                 "unavailable: %s", filename, pcmk_rc_str(rc));
        return pcmk_rc_ok;
    }
    if ((st.st_gid == pcmk_gid)
        && ((st.st_mode & S_IRWXG) == (S_IRGRP|S_IWGRP))) {
        return pcmk_rc_ok;
    }
    if (fchown(logfd, pcmk_uid, pcmk_gid) < 0) {
        crm_warn("Couldn't change '%s' ownership to user %s gid %d: %s",
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
        crm_warn("Couldn't change '%s' mode to %04o: %s",
                 filename, filemode, strerror(errno));
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
        crm_warn("Logging to '%s' is disabled: %s " QB_XS " uid=%u gid=%u",
                 filename, strerror(rc), geteuid(), getegid());
        return rc;
    }

    rc = set_logfile_permissions(filename, logfile);
    if (rc != pcmk_rc_ok) {
        crm_warn("Logging to '%s' is disabled: %s " QB_XS " permissions",
                 filename, strerror(rc));
        fclose(logfile);
        return rc;
    }

    // Close and reopen as libqb logging target
    fclose(logfile);
    fd = qb_log_file_open(filename);
    if (fd < 0) {
        crm_warn("Logging to '%s' is disabled: %s " QB_XS " qb_log_file_open",
                 filename, strerror(-fd));
        return -fd; // == +errno
    }

    if (is_default) {
        default_fd = fd;
        setenv_logfile(filename);

    } else if (default_fd >= 0) {
        crm_notice("Switching logging to %s", filename);
        disable_logfile(default_fd);
    }

    crm_notice("Additional logging available in %s", filename);
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

static int blackbox_trigger = 0;
static volatile char *blackbox_file_prefix = NULL;

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

static void
crm_control_blackbox(int nsig, bool enable)
{
    int lpc = 0;

    if (blackbox_file_prefix == NULL) {
        pid_t pid = getpid();

        blackbox_file_prefix = crm_strdup_printf("%s/%s-%lu",
                                                 CRM_BLACKBOX_DIR,
                                                 crm_system_name,
                                                 (unsigned long) pid);
    }

    if (enable && qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_STATE_GET, 0) != QB_LOG_STATE_ENABLED) {
        qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_SIZE, 5 * 1024 * 1024); /* Any size change drops existing entries */
        qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_TRUE);      /* Setting the size seems to disable it */

        /* Enable synchronous logging */
        for (lpc = QB_LOG_BLACKBOX; lpc < QB_LOG_TARGET_MAX; lpc++) {
            qb_log_ctl(lpc, QB_LOG_CONF_FILE_SYNC, QB_TRUE);
        }

        crm_notice("Initiated blackbox recorder: %s", blackbox_file_prefix);

        /* Save to disk on abnormal termination */
        crm_signal_handler(SIGSEGV, crm_trigger_blackbox);
        crm_signal_handler(SIGABRT, crm_trigger_blackbox);
        crm_signal_handler(SIGILL,  crm_trigger_blackbox);
        crm_signal_handler(SIGBUS,  crm_trigger_blackbox);
        crm_signal_handler(SIGFPE,  crm_trigger_blackbox);

        crm_update_callsites();

        blackbox_trigger = qb_log_custom_open(blackbox_logger, NULL, NULL, NULL);
        qb_log_ctl(blackbox_trigger, QB_LOG_CONF_ENABLED, QB_TRUE);
        crm_trace("Trigger: %d is %d %d", blackbox_trigger,
                  qb_log_ctl(blackbox_trigger, QB_LOG_CONF_STATE_GET, 0), QB_LOG_STATE_ENABLED);

        crm_update_callsites();

    } else if (!enable && qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_STATE_GET, 0) == QB_LOG_STATE_ENABLED) {
        qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_FALSE);

        /* Disable synchronous logging again when the blackbox is disabled */
        for (lpc = QB_LOG_BLACKBOX; lpc < QB_LOG_TARGET_MAX; lpc++) {
            qb_log_ctl(lpc, QB_LOG_CONF_FILE_SYNC, QB_FALSE);
        }
    }
}

void
crm_enable_blackbox(int nsig)
{
    crm_control_blackbox(nsig, TRUE);
}

void
crm_disable_blackbox(int nsig)
{
    crm_control_blackbox(nsig, FALSE);
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

    char buffer[NAME_MAX];
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

            snprintf(buffer, NAME_MAX, "%s.%d", blackbox_file_prefix, counter++);
            if (nsig == SIGTRAP) {
                crm_notice("Blackbox dump requested, please see %s for contents", buffer);

            } else if (cs) {
                syslog(LOG_NOTICE,
                       "Problem detected at %s:%d (%s), please see %s for additional details",
                       cs->function, cs->lineno, cs->filename, buffer);
            } else {
                crm_notice("Problem detected, please see %s for additional details", buffer);
            }

            last = now;
            qb_log_blackbox_write_to_file(buffer);

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
crm_log_filter_source(int source, const char *trace_files, const char *trace_fns,
                      const char *trace_fmts, const char *trace_tags, const char *trace_blackbox,
                      struct qb_log_callsite *cs)
{
    if (qb_log_ctl(source, QB_LOG_CONF_STATE_GET, 0) != QB_LOG_STATE_ENABLED) {
        return;
    } else if (cs->tags != crm_trace_nonlog && source == QB_LOG_BLACKBOX) {
        /* Blackbox gets everything if enabled */
        qb_bit_set(cs->targets, source);

    } else if (source == blackbox_trigger && blackbox_trigger > 0) {
        /* Should this log message result in the blackbox being dumped */
        if (cs->priority <= LOG_ERR) {
            qb_bit_set(cs->targets, source);

        } else if (trace_blackbox) {
            char *key = crm_strdup_printf("%s:%d", cs->function, cs->lineno);

            if (strstr(trace_blackbox, key) != NULL) {
                qb_bit_set(cs->targets, source);
            }
            free(key);
        }

    } else if (source == QB_LOG_SYSLOG) {       /* No tracing to syslog */
        if (cs->priority <= crm_log_priority && cs->priority <= crm_log_level) {
            qb_bit_set(cs->targets, source);
        }
        /* Log file tracing options... */
    } else if (cs->priority <= crm_log_level) {
        qb_bit_set(cs->targets, source);
    } else if (trace_files && strstr(trace_files, cs->filename) != NULL) {
        qb_bit_set(cs->targets, source);
    } else if (trace_fns && strstr(trace_fns, cs->function) != NULL) {
        qb_bit_set(cs->targets, source);
    } else if (trace_fmts && strstr(trace_fmts, cs->format) != NULL) {
        qb_bit_set(cs->targets, source);
    } else if (trace_tags
               && cs->tags != 0
               && cs->tags != crm_trace_nonlog && g_quark_to_string(cs->tags) != NULL) {
        qb_bit_set(cs->targets, source);
    }
}

#ifndef HAVE_STRCHRNUL
/* strchrnul() is a GNU extension. If not present, use our own definition.
 * The GNU version returns char*, but we only need it to be const char*.
 */
static const char *
strchrnul(const char *s, int c)
{
    while ((*s != c) && (*s != '\0')) {
        ++s;
    }
    return s;
}
#endif

static void
crm_log_filter(struct qb_log_callsite *cs)
{
    int lpc = 0;
    static int need_init = 1;
    static const char *trace_fns = NULL;
    static const char *trace_tags = NULL;
    static const char *trace_fmts = NULL;
    static const char *trace_files = NULL;
    static const char *trace_blackbox = NULL;

    if (need_init) {
        need_init = 0;
        trace_fns = pcmk__env_option(PCMK__ENV_TRACE_FUNCTIONS);
        trace_fmts = pcmk__env_option(PCMK__ENV_TRACE_FORMATS);
        trace_tags = pcmk__env_option(PCMK__ENV_TRACE_TAGS);
        trace_files = pcmk__env_option(PCMK__ENV_TRACE_FILES);
        trace_blackbox = pcmk__env_option(PCMK__ENV_TRACE_BLACKBOX);

        if (trace_tags != NULL) {
            uint32_t tag;
            char token[500];
            const char *offset = NULL;
            const char *next = trace_tags;

            do {
                offset = next;
                next = strchrnul(offset, ',');
                snprintf(token, sizeof(token), "%.*s", (int)(next - offset), offset);

                tag = g_quark_from_string(token);
                crm_info("Created GQuark %u from token '%s' in '%s'", tag, token, trace_tags);

                if (next[0] != 0) {
                    next++;
                }

            } while (next != NULL && next[0] != 0);
        }
    }

    cs->targets = 0;            /* Reset then find targets to enable */
    for (lpc = QB_LOG_SYSLOG; lpc < QB_LOG_TARGET_MAX; lpc++) {
        crm_log_filter_source(lpc, trace_files, trace_fns, trace_fmts, trace_tags, trace_blackbox,
                              cs);
    }
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
    static gboolean log = TRUE;

    if (log) {
        log = FALSE;
        crm_debug
            ("Enabling callsites based on priority=%d, files=%s, functions=%s, formats=%s, tags=%s",
             crm_log_level, pcmk__env_option(PCMK__ENV_TRACE_FILES),
             pcmk__env_option(PCMK__ENV_TRACE_FUNCTIONS),
             pcmk__env_option(PCMK__ENV_TRACE_FORMATS),
             pcmk__env_option(PCMK__ENV_TRACE_TAGS));
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
    int lpc;

    for (lpc = 0; name != NULL && p_names[lpc].name != NULL; lpc++) {
        if (pcmk__str_eq(p_names[lpc].name, name, pcmk__str_none)) {
            return p_names[lpc].priority;
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

    struct utsname res;
    int lpc = 0;
    int32_t qb_facility = 0;
    pid_t pid = getpid();
    const char *nodename = "localhost";
    static bool have_logging = false;
    GLogLevelFlags log_levels;

    if (have_logging) {
        return;
    }

    have_logging = true;

    /* @TODO Try to create a more obvious "global Pacemaker initializer"
     * function than crm_log_preinit(), and call pcmk__schema_init() there.
     * See also https://projects.clusterlabs.org/T840.
     */
    pcmk__schema_init();

    if (crm_trace_nonlog == 0) {
        crm_trace_nonlog = g_quark_from_static_string("Pacemaker non-logging tracepoint");
    }

    umask(S_IWGRP | S_IWOTH | S_IROTH);

    /* Add a log handler for messages from our log domain at any log level. */
    log_levels = G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION;
    pcmk__log_id = g_log_set_handler(G_LOG_DOMAIN, log_levels, crm_glib_handler, NULL);
    /* Add a log handler for messages from the GLib domains at any log level. */
    pcmk__glib_log_id = g_log_set_handler("GLib", log_levels, crm_glib_handler, NULL);
    pcmk__gio_log_id = g_log_set_handler("GLib-GIO", log_levels, crm_glib_handler, NULL);
    pcmk__gmodule_log_id = g_log_set_handler("GModule", log_levels, crm_glib_handler, NULL);
    pcmk__gthread_log_id = g_log_set_handler("GThread", log_levels, crm_glib_handler, NULL);

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

    qb_facility = qb_log_facility2int("local0");
    qb_log_init(crm_system_name, qb_facility, LOG_ERR);
    crm_log_level = LOG_CRIT;

    /* Nuke any syslog activity until it's asked for */
    qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_FALSE);
#ifdef HAVE_qb_log_conf_QB_LOG_CONF_MAX_LINE_LEN
    // Shorter than default, generous for what we *should* send to syslog
    qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_MAX_LINE_LEN, 256);
#endif
    if (uname(memset(&res, 0, sizeof(res))) == 0 && *res.nodename != '\0') {
        nodename = res.nodename;
    }

    /* Set format strings and disable threading
     * Pacemaker and threads do not mix well (due to the amount of forking)
     */
    qb_log_tags_stringify_fn_set(crm_quark_to_string);
    for (lpc = QB_LOG_SYSLOG; lpc < QB_LOG_TARGET_MAX; lpc++) {
        qb_log_ctl(lpc, QB_LOG_CONF_THREADED, QB_FALSE);
#ifdef HAVE_qb_log_conf_QB_LOG_CONF_ELLIPSIS
        // End truncated lines with '...'
        qb_log_ctl(lpc, QB_LOG_CONF_ELLIPSIS, QB_TRUE);
#endif
        set_format_string(lpc, crm_system_name, pid, nodename);
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
    crm_trace("Quiet: %d, facility %s", quiet, f_copy);
    pcmk__env_option(PCMK__ENV_LOGFILE);
    pcmk__env_option(PCMK__ENV_LOGFACILITY);

    crm_update_callsites();

    /* Ok, now we can start logging... */

    // Disable daemon request if user isn't root or Pacemaker daemon user
    if (pcmk__is_daemon) {
        const char *user = getenv("USER");

        if (user != NULL && !pcmk__strcase_any_of(user, "root", CRM_DAEMON_USER, NULL)) {
            crm_trace("Not switching to corefile directory for %s", user);
            pcmk__is_daemon = false;
        }
    }

    if (pcmk__is_daemon) {
        int user = getuid();
        struct passwd *pwent = getpwuid(user);

        if (pwent == NULL) {
            crm_perror(LOG_ERR, "Cannot get name for uid: %d", user);

        } else if (!pcmk__strcase_any_of(pwent->pw_name, "root", CRM_DAEMON_USER, NULL)) {
            crm_trace("Don't change active directory for regular user: %s", pwent->pw_name);

        } else if (chdir(CRM_CORE_DIR) < 0) {
            crm_perror(LOG_INFO, "Cannot change active directory to " CRM_CORE_DIR);

        } else {
            crm_info("Changed active directory to " CRM_CORE_DIR);
        }

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
        mainloop_add_signal(SIGTRAP, crm_trigger_blackbox);

    } else if (!quiet) {
        crm_log_args(argc, argv);
    }

    return TRUE;
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
    crm_trace("New log level: %d", level);
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
    crm_notice("Invoked: %s", arg_string);
    g_free(arg_string);
}

void
crm_log_output_fn(const char *file, const char *function, int line, int level, const char *prefix,
                  const char *output)
{
    const char *next = NULL;
    const char *offset = NULL;

    if (level == LOG_NEVER) {
        return;
    }

    if (output == NULL) {
        if (level != LOG_STDOUT) {
            level = LOG_TRACE;
        }
        output = "-- empty --";
    }

    next = output;
    do {
        offset = next;
        next = strchrnul(offset, '\n');
        do_crm_log_alias(level, file, function, line, "%s [ %.*s ]", prefix,
                         (int)(next - offset), offset);
        if (next[0] != 0) {
            next++;
        }

    } while (next != NULL && next[0] != 0);
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
 * \note This does nothing when \p level is \p LOG_STDOUT.
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
 * \note This does nothing when \p level is \c LOG_STDOUT.
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
 * \note This does nothing when \p level is \c LOG_STDOUT.
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

/*!
 * \internal
 * \brief Free the logging library's internal log output object
 */
void
pcmk__free_common_logger(void)
{
    if (logger_out != NULL) {
        logger_out->finish(logger_out, CRM_EX_OK, true, NULL);
        pcmk__output_free(logger_out);
        logger_out = NULL;
    }
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
