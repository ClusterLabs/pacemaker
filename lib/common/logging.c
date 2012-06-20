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

#include <qb/qbdefs.h>

#include <crm/crm.h>
#include <crm/common/mainloop.h>

unsigned int crm_log_level = LOG_INFO;
static gboolean crm_tracing_enabled(void);

#ifdef HAVE_G_LOG_SET_DEFAULT_HANDLER
GLogFunc glib_log_default;

static void
crm_glib_handler(const gchar * log_domain, GLogLevelFlags flags, const gchar * message,
                 gpointer user_data)
{
    int log_level = LOG_WARNING;
    GLogLevelFlags msg_level = (flags & G_LOG_LEVEL_MASK);

    switch (msg_level) {
        case G_LOG_LEVEL_CRITICAL:
            /* log and record how we got here */
            crm_abort(__FILE__, __PRETTY_FUNCTION__, __LINE__, message, TRUE, TRUE);
            return;

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
        case G_LOG_FLAG_RECURSION:
        case G_LOG_FLAG_FATAL:
        case G_LOG_LEVEL_MASK:
            log_level = LOG_WARNING;
            break;
    }

    do_crm_log(log_level, "%s: %s", log_domain, message);
}
#endif

#ifndef NAME_MAX
#  define NAME_MAX 256
#endif
static const char *
daemon_option(const char *option)
{
    char env_name[NAME_MAX];
    const char *value = NULL;

    snprintf(env_name, NAME_MAX, "PCMK_%s", option);
    value = getenv(env_name);
    if (value != NULL) {
        return value;
    }

    snprintf(env_name, NAME_MAX, "HA_%s", option);
    value = getenv(env_name);
    if (value != NULL) {
        return value;
    }

    return NULL;
}

static gboolean
daemon_option_enabled(const char *daemon, const char *option)
{
    const char *value = daemon_option(option);
    if (value != NULL && crm_is_true(value)) {
        return TRUE;

    } else if (value != NULL && strstr(value, daemon)) {
        return TRUE;
    }

    return FALSE;
}

void
crm_log_deinit(void)
{
#ifdef HAVE_G_LOG_SET_DEFAULT_HANDLER
    g_log_set_default_handler(glib_log_default, NULL);
#endif
}

#define FMT_MAX 256
static void
set_format_string(int method, const char *daemon)
{
    int offset = 0;
    char fmt[FMT_MAX];

    if (method > QB_LOG_STDERR) {
        /* When logging to a file */
        struct utsname res;

        if (uname(&res) == 0) {
            offset +=
                snprintf(fmt + offset, FMT_MAX - offset, "%%t [%d] %s %10s: ", getpid(),
                         res.nodename, daemon);
        } else {
            offset += snprintf(fmt + offset, FMT_MAX - offset, "%%t [%d] %10s: ", getpid(), daemon);
        }
    }

    if (crm_tracing_enabled() && method >= QB_LOG_STDERR) {
        offset += snprintf(fmt + offset, FMT_MAX - offset, "(%%-12f:%%5l %%g) %%-7p: %%n: ");
    } else {
        offset += snprintf(fmt + offset, FMT_MAX - offset, "%%g %%-7p: %%n: ");
    }

    if (method == QB_LOG_SYSLOG) {
        offset += snprintf(fmt + offset, FMT_MAX - offset, "%%b");
    } else {
        offset += snprintf(fmt + offset, FMT_MAX - offset, "\t%%b");
    }
    qb_log_format_set(method, fmt);
}

gboolean
crm_add_logfile(const char *filename)
{
    struct stat parent;
    int fd = 0, rc = 0;
    FILE *logfile = NULL;
    char *parent_dir = NULL;

    static gboolean have_logfile = FALSE;

    if(filename == NULL && have_logfile == FALSE) {
        filename = "/var/log/pacemaker.log";
    }
    
    if (filename == NULL) {
        return FALSE; /* Nothing to do */
    }

    /* Check the parent directory and attempt to open */
    parent_dir = dirname(strdup(filename));
    rc = stat(parent_dir, &parent);

    if (rc != 0) {
        crm_err("Directory '%s' does not exist: logging to '%s' is disabled", parent_dir, filename);
        return FALSE;
        
    } else if (parent.st_uid == geteuid() && (parent.st_mode & (S_IRUSR | S_IWUSR))) {
        /* all good - user */
        logfile = fopen(filename, "a");
        
    } else if (parent.st_gid == getegid() && (parent.st_mode & S_IXGRP)) {
        /* all good - group */
        logfile = fopen(filename, "a");

    } else {
        crm_err("We (uid=%u, gid=%u) do not have permission to access '%s': logging to '%s' is disabled",
                geteuid(), getegid(), parent_dir, filename);
        return FALSE;
    }

    /* Check/Set permissions if we're root */
    if(logfile && geteuid() == 0) {
        struct stat st;
        uid_t pcmk_uid = 0;
        gid_t pcmk_gid = 0;
        gboolean fix = FALSE;
        int logfd = fileno(logfile);

        rc = fstat(logfd, &st);
        if(rc < 0) {
            crm_perror(LOG_WARNING, "Cannot stat %s", filename);
            fclose(logfile);
            return FALSE;
        }

        crm_user_lookup(CRM_DAEMON_USER, &pcmk_uid, &pcmk_gid);
        if(st.st_gid != pcmk_gid) {
            /* Wrong group */
            fix = TRUE;
        } else if((st.st_mode & S_IRWXG) != (S_IRGRP|S_IWGRP)) {
            /* Not read/writable by the correct group */
            fix = TRUE;
        }

        if(fix) {
            rc = fchown(logfd, pcmk_uid, pcmk_gid);
            if(rc < 0) {
                crm_warn("Cannot change the ownership of %s to user %s and gid %d",
                         filename, CRM_DAEMON_USER, pcmk_gid);
            }

            rc = fchmod(logfd, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
            if(rc < 0) {
                crm_warn("Cannot change the mode of %s to rw-rw----", filename);
            }

            fprintf(logfile, "Set r/w permissions for uid=%d, gid=%d on %s\n",
                    pcmk_uid, pcmk_gid, filename);
            if(fflush(logfile) < 0 || fsync(logfd) < 0) {
                crm_err("Couldn't write out logfile: %s", filename);
            }
        }
    }
    if(logfile) {
        fclose(logfile);
    }

    /* Now open with libqb */
    fd = qb_log_file_open(filename);

    if(fd < 0) {
        crm_perror(LOG_WARNING, "Couldn't send additional logging to %s", filename);
        return FALSE;
    }

    crm_notice("Additional logging available in %s", filename);
    qb_log_ctl(fd, QB_LOG_CONF_ENABLED, QB_TRUE);

    /* Enable callsites */
    crm_update_callsites();
    have_logfile = TRUE;
    return TRUE;
}


static char *blackbox_file_prefix = NULL;
static gboolean blackbox_tracing_enabled = FALSE;

void
crm_enable_blackbox_tracing(int nsig) 
{

    if(blackbox_tracing_enabled) {
        blackbox_tracing_enabled = FALSE;
    } else {
        blackbox_tracing_enabled = TRUE;
    }
    crm_update_callsites();
    crm_debug("Blackbox tracing is %s", blackbox_tracing_enabled?"on":"off");
}

void
crm_enable_blackbox(int nsig)
{
    if(blackbox_file_prefix == NULL) {
        pid_t pid = getpid();

        blackbox_file_prefix = malloc(NAME_MAX);
        snprintf(blackbox_file_prefix, NAME_MAX, "%s/blackbox-%s-%d", CRM_BLACKBOX_DIR, crm_system_name, pid);
    }

    if (qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_STATE_GET, 0) != QB_LOG_STATE_ENABLED) {
        qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_SIZE, 1024*1024); /* Any size change drops existing entries */
        qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_ENABLED, QB_TRUE); /* Setting the size seems to disable it */

        crm_notice("Initiated blackbox recorder: %s", blackbox_file_prefix);
        crm_signal(SIGSEGV, crm_write_blackbox);
        crm_update_callsites();

        /* Original meanings from signal(7) 
         *
         * Signal       Value     Action   Comment
         * SIGPROF     27,27,29    Term    Profiling timer expired
         * SIGTRAP        5        Core    Trace/breakpoint trap
         *
         * Our usage is as similar as possible
         */
        mainloop_add_signal(SIGPROF, crm_enable_blackbox_tracing);
        mainloop_add_signal(SIGTRAP, crm_write_blackbox);
    }
}

void
crm_write_blackbox(int nsig)
{
    static int counter = 1;
    static time_t last = 0;

    char buffer[NAME_MAX];
    time_t now = time(NULL);

    if(blackbox_file_prefix == NULL) {
        return;
    }

    switch(nsig) {
        case 0:
        case SIGTRAP:
            /* The graceful case - such as assertion failure or user request */
            snprintf(buffer, NAME_MAX, "%s.%d", blackbox_file_prefix, counter++);

            if(nsig == 0 && (now - last) < 2) {
                /* Prevent over-dumping */
                return;

            } else if(nsig == SIGTRAP) {
                crm_notice("Blackbox dump requested, please see %s for contents", buffer);

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
            crm_signal(nsig, SIG_DFL);
            qb_log_blackbox_write_to_file(blackbox_file_prefix);
            qb_log_fini();
            raise(nsig);
            break;
    }
}

gboolean
crm_log_cli_init(const char *entity)
{
    return crm_log_init(entity, LOG_ERR, FALSE, FALSE, 0, NULL, TRUE);
}

static const char *crm_quark_to_string(uint32_t tag)
{
    const char *text = g_quark_to_string(tag);
    if(text) {
        return text;
    }
    return "";
}

static void
crm_log_filter_source(int source, const char *trace_files, const char *trace_fns, const char *trace_fmts, const char *trace_tags, struct qb_log_callsite *cs)
{
    if (qb_log_ctl(source, QB_LOG_CONF_STATE_GET, 0) != QB_LOG_STATE_ENABLED) {
        return;
    } else if (source == QB_LOG_SYSLOG) { /* No tracing to syslog */
        if(cs->priority <= LOG_NOTICE && cs->priority <= crm_log_level) {
            qb_bit_set(cs->targets, source);
        }
        /* Tracing options... */
    } else if(source == QB_LOG_BLACKBOX && blackbox_tracing_enabled) {
        qb_bit_set(cs->targets, source);
    } else if (cs->priority <= crm_log_level) {
        qb_bit_set(cs->targets, source);
    } else if(trace_files && strstr(trace_files, cs->filename) != NULL) {
        qb_bit_set(cs->targets, source);
    } else if(trace_fns && strstr(trace_fns, cs->function) != NULL) {
        qb_bit_set(cs->targets, source);
    } else if(trace_fmts && strstr(trace_fmts, cs->format) != NULL) {
        qb_bit_set(cs->targets, source);
    } else if(trace_tags && cs->tags != 0 && g_quark_to_string(cs->tags) != NULL) {
        qb_bit_set(cs->targets, source);
    }
}

static void
crm_log_filter(struct qb_log_callsite *cs)
{
    int lpc = 0;
    static int need_init = 1;
    static const char *trace_fns = NULL;
    static const char *trace_tags = NULL;
    static const char *trace_fmts = NULL;
    static const char *trace_files = NULL;

    if(need_init) {
        need_init = 0;
        trace_fns = getenv("PCMK_trace_functions");
        trace_fmts = getenv("PCMK_trace_formats");
        trace_tags = getenv("PCMK_trace_tags");
        trace_files = getenv("PCMK_trace_files");

        if (trace_tags != NULL) {
            uint32_t tag;
            char token[500];
            const char *offset = NULL;
            const char *next = trace_tags;

            do {
                offset = next;
                next = strchrnul(offset, ',');
                snprintf(token, 499, "%.*s", (int)(next - offset), offset);

                tag = g_quark_from_string(token);
                crm_info("Created GQuark %u from token '%s' in '%s'", tag, token, trace_tags);

                if (next[0] != 0) {
                    next++;
                }

            } while (next != NULL && next[0] != 0);
        }
    }

    cs->targets = 0; /* Reset then find targets to enable */
    for (lpc = QB_LOG_SYSLOG; lpc < QB_LOG_TARGET_MAX; lpc++) {
        crm_log_filter_source(lpc, trace_files, trace_fns, trace_fmts, trace_tags, cs);
    }
}

gboolean
crm_is_callsite_active(struct qb_log_callsite *cs, int level)
{
    if (cs == NULL) {
        return FALSE;
    }

    if(cs->priority != level) {
        cs->priority = level;
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
    crm_info("Enabling callsites based on priority=%d, files=%s, functions=%s, formats=%s, tags=%s",
             crm_log_level, 
             getenv("PCMK_trace_files"),
             getenv("PCMK_trace_functions"),
             getenv("PCMK_trace_formats"),
             getenv("PCMK_trace_tags"));
    qb_log_filter_fn_set(crm_log_filter);
}

static gboolean
crm_tracing_enabled(void)
{
    if(crm_log_level >= LOG_TRACE) {
        return TRUE;
    } else if(getenv("PCMK_trace_files") || getenv("PCMK_trace_functions") || getenv("PCMK_trace_formats")  || getenv("PCMK_trace_tags")) {
        return TRUE;
    }
    return FALSE;
}

gboolean
crm_log_init(const char *entity, int level, gboolean daemon, gboolean to_stderr,
             int argc, char **argv, gboolean quiet)
{
    int lpc = 0;
    const char *logfile = daemon_option("debugfile");
    const char *facility = daemon_option("logfacility");

    /* Redirect messages from glib functions to our handler */
#ifdef HAVE_G_LOG_SET_DEFAULT_HANDLER
    glib_log_default = g_log_set_default_handler(crm_glib_handler, NULL);
#endif

    /* and for good measure... - this enum is a bit field (!) */
    g_log_set_always_fatal((GLogLevelFlags) 0); /*value out of range */

    if (facility == NULL) {
        /* Set a default */
        facility = "daemon";
    }

    if (entity) {
        crm_system_name = entity;

    } else if (argc > 0 && argv != NULL) {
        char *mutable = crm_strdup(argv[0]);

        crm_system_name = basename(mutable);
        if (strstr(crm_system_name, "lt-") == crm_system_name) {
            crm_system_name += 3;
        }

    } else if (crm_system_name == NULL) {
        crm_system_name = "Unknown";
    }

    setenv("PCMK_service", crm_system_name, 1);

    if (daemon_option_enabled(crm_system_name, "debug")) {
        /* Override the default setting */
        level = LOG_DEBUG;
    }

    if (daemon_option_enabled(crm_system_name, "stderr")) {
        /* Override the default setting */
        to_stderr = TRUE;
    }

    crm_log_level = level;
    qb_log_init(crm_system_name, qb_log_facility2int(facility), level);
    qb_log_tags_stringify_fn_set(crm_quark_to_string);

    /* Set default format strings */
    for (lpc = QB_LOG_SYSLOG; lpc < QB_LOG_TARGET_MAX; lpc++) {
        set_format_string(lpc, crm_system_name);
    }

    if (quiet) {
        /* Nuke any syslog activity */
        unsetenv("HA_logfacility");
        unsetenv("PCMK_logfacility");
        qb_log_ctl(QB_LOG_SYSLOG, QB_LOG_CONF_ENABLED, QB_FALSE);

    } else {
        crm_log_args(argc, argv);
        if(daemon) {
            setenv("HA_logfacility", facility, TRUE);
            setenv("PCMK_logfacility", facility, TRUE);
        }
    }

    if (daemon_option_enabled(crm_system_name, "blackbox")) {
        crm_enable_blackbox(0);
    }
    
    crm_enable_stderr(to_stderr);

    if(logfile) {
        crm_add_logfile(logfile);
    }

    if(daemon
       && crm_tracing_enabled()
       && qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_STATE_GET, 0) != QB_LOG_STATE_ENABLED
       && qb_log_ctl(QB_LOG_BLACKBOX, QB_LOG_CONF_STATE_GET, 0) != QB_LOG_STATE_ENABLED) {
        /* Make sure tracing goes somewhere */
        crm_add_logfile(NULL);
    }

    crm_update_callsites();
    
    /* Ok, now we can start logging... */

    if (daemon) {
        const char *user = getenv("USER");

        if (user != NULL && safe_str_neq(user, "root") && safe_str_neq(user, CRM_DAEMON_USER)) {
            crm_trace("Not switching to corefile directory for %s", user);
            daemon = FALSE;
        }
    }

    if (daemon) {
        int user = getuid();
        const char *base = CRM_CORE_DIR;
        struct passwd *pwent = getpwuid(user);

        if (pwent == NULL) {
            crm_perror(LOG_ERR, "Cannot get name for uid: %d", user);

        } else if (safe_str_neq(pwent->pw_name, "root")
                   && safe_str_neq(pwent->pw_name, "nobody")
                   && safe_str_neq(pwent->pw_name, CRM_DAEMON_USER)) {
            crm_debug("Don't change active directory for regular user: %s", pwent->pw_name);

        } else if (chdir(base) < 0) {
            crm_perror(LOG_ERR, "Cannot change active directory to %s", base);

        } else if (chdir(pwent->pw_name) < 0) {
            crm_perror(LOG_ERR, "Cannot change active directory to %s/%s", base, pwent->pw_name);
        } else {
            crm_info("Changed active directory to %s/%s", base, pwent->pw_name);
#if 0
            {
                char path[512];

                snprintf(path, 512, "%s-%d", crm_system_name, getpid());
                mkdir(path, 0750);
                chdir(path);
                crm_info("Changed active directory to %s/%s/%s", base, pwent->pw_name, path);
            }
#endif
        }
        mainloop_add_signal(SIGUSR1, crm_enable_blackbox);
    }

    return TRUE;
}

/* returns the old value */
unsigned int
set_crm_log_level(unsigned int level)
{
    unsigned int old = crm_log_level;
    crm_log_level = level;
    crm_update_callsites();
    crm_info("New log level: %d", level);
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

void
crm_bump_log_level(void)
{
    if (qb_log_ctl(QB_LOG_STDERR, QB_LOG_CONF_STATE_GET, 0) == QB_LOG_STATE_ENABLED) {
        set_crm_log_level(crm_log_level + 1);
    }
    crm_enable_stderr(TRUE);
}

unsigned int
get_crm_log_level(void)
{
    return crm_log_level;
}

void
crm_log_args(int argc, char **argv)
{
    int lpc = 0;
    int len = 0;
    int existing_len = 0;
    char *arg_string = NULL;

    if (argc == 0 || argv == NULL) {
        return;
    }

    for (; lpc < argc; lpc++) {
        if (argv[lpc] == NULL) {
            break;
        }

        len = 2 + strlen(argv[lpc]);    /* +1 space, +1 EOS */
        arg_string = realloc(arg_string, len + existing_len);
        existing_len += sprintf(arg_string + existing_len, "%s ", argv[lpc]);
    }
    do_crm_log_always(LOG_NOTICE, "Invoked: %s", arg_string);
    free(arg_string);
}
