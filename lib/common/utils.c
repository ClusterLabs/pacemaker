/*
 * Copyright 2004-2020 the Pacemaker project contributors
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

#include <sys/types.h>
#include <sys/wait.h>
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

#include <qb/qbdefs.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/msg_xml.h>
#include <crm/cib/internal.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/common/ipc.h>
#include <crm/common/iso8601.h>
#include <crm/common/mainloop.h>
#include <libxml2/libxml/relaxng.h>

#ifndef MAXLINE
#  define MAXLINE 512
#endif

#ifndef PW_BUFFER_LEN
#  define PW_BUFFER_LEN		500
#endif

CRM_TRACE_INIT_DATA(common);

gboolean crm_config_error = FALSE;
gboolean crm_config_warning = FALSE;
char *crm_system_name = NULL;

int pcmk__score_red = 0;
int pcmk__score_green = 0;
int pcmk__score_yellow = 0;

int
char2score(const char *score)
{
    int score_f = 0;

    if (score == NULL) {

    } else if (pcmk_str_is_minus_infinity(score)) {
        score_f = -CRM_SCORE_INFINITY;

    } else if (pcmk_str_is_infinity(score)) {
        score_f = CRM_SCORE_INFINITY;

    } else if (safe_str_eq(score, "red")) {
        score_f = pcmk__score_red;

    } else if (safe_str_eq(score, "yellow")) {
        score_f = pcmk__score_yellow;

    } else if (safe_str_eq(score, "green")) {
        score_f = pcmk__score_green;

    } else {
        score_f = crm_parse_int(score, NULL);
        if (score_f > 0 && score_f > CRM_SCORE_INFINITY) {
            score_f = CRM_SCORE_INFINITY;

        } else if (score_f < 0 && score_f < -CRM_SCORE_INFINITY) {
            score_f = -CRM_SCORE_INFINITY;
        }
    }

    return score_f;
}

char *
score2char_stack(int score, char *buf, size_t len)
{
    if (score >= CRM_SCORE_INFINITY) {
        strncpy(buf, CRM_INFINITY_S, 9);
    } else if (score <= -CRM_SCORE_INFINITY) {
        strncpy(buf, CRM_MINUS_INFINITY_S , 10);
    } else {
        return crm_itoa_stack(score, buf, len);
    }

    return buf;
}

char *
score2char(int score)
{
    if (score >= CRM_SCORE_INFINITY) {
        return strdup(CRM_INFINITY_S);

    } else if (score <= -CRM_SCORE_INFINITY) {
        return strdup(CRM_MINUS_INFINITY_S);
    }
    return crm_itoa(score);
}

char *
generate_hash_key(const char *crm_msg_reference, const char *sys)
{
    char *hash_key = crm_strdup_printf("%s_%s", (sys? sys : "none"),
                                       crm_msg_reference);

    crm_trace("created hash key: (%s)", hash_key);
    return hash_key;
}


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
    int rc = pcmk_err_generic;

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
crm_version_helper(const char *text, const char **end_text)
{
    int atoi_result = -1;

    CRM_ASSERT(end_text != NULL);

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
            digit1 = crm_version_helper(ver1_iter, &ver1_iter);
        }

        if (ver2_iter != NULL) {
            digit2 = crm_version_helper(ver2_iter, &ver2_iter);
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
 * \brief Parse milliseconds from a Pacemaker interval specification
 *
 * \param[in] input  Pacemaker time interval specification (a bare number of
 *                   seconds, a number with a unit optionally with whitespace
 *                   before and/or after the number, or an ISO 8601 duration)
 *
 * \return Milliseconds equivalent of given specification on success (limited
 *         to the range of an unsigned integer), 0 if input is NULL,
 *         or 0 (and set errno to EINVAL) on error
 */
guint
crm_parse_interval_spec(const char *input)
{
    long long msec = -1;

    errno = 0;
    if (input == NULL) {
        return 0;

    } else if (input[0] == 'P') {
        crm_time_t *period_s = crm_time_parse_duration(input);

        if (period_s) {
            msec = 1000 * crm_time_get_seconds(period_s);
            crm_time_free(period_s);
        }

    } else {
        msec = crm_get_msec(input);
    }

    if (msec < 0) {
        crm_warn("Using 0 instead of '%s'", input);
        errno = EINVAL;
        return 0;
    }
    return (msec >= G_MAXUINT)? G_MAXUINT : (guint) msec;
}

extern bool crm_is_daemon;

/* coverity[+kill] */
void
crm_abort(const char *file, const char *function, int line,
          const char *assert_condition, gboolean do_core, gboolean do_fork)
{
    int rc = 0;
    int pid = 0;
    int status = 0;

    /* Implied by the parent's error logging below */
    /* crm_write_blackbox(0); */

    if(crm_is_daemon == FALSE) {
        /* This is a command line tool - do not fork */

        /* crm_add_logfile(NULL);   * Record it to a file? */
        crm_enable_stderr(TRUE); /* Make sure stderr is enabled so we can tell the caller */
        do_fork = FALSE;         /* Just crash if needed */
    }

    if (do_core == FALSE) {
        crm_err("%s: Triggered assert at %s:%d : %s", function, file, line, assert_condition);
        return;

    } else if (do_fork) {
        pid = fork();

    } else {
        crm_err("%s: Triggered fatal assert at %s:%d : %s", function, file, line, assert_condition);
    }

    if (pid == -1) {
        crm_crit("%s: Cannot create core for non-fatal assert at %s:%d : %s",
                 function, file, line, assert_condition);
        return;

    } else if(pid == 0) {
        /* Child process */
        abort();
        return;
    }

    /* Parent process */
    crm_err("%s: Forked child %d to record non-fatal assert at %s:%d : %s",
            function, pid, file, line, assert_condition);
    crm_write_blackbox(SIGTRAP, NULL);

    do {
        rc = waitpid(pid, &status, 0);
        if(rc == pid) {
            return; /* Job done */
        }

    } while(errno == EINTR);

    if (errno == ECHILD) {
        /* crm_mon does this */
        crm_trace("Cannot wait on forked child %d - SIGCHLD is probably set to SIG_IGN", pid);
        return;
    }
    crm_perror(LOG_ERR, "Cannot wait on forked child %d", pid);
}

void
crm_make_daemon(const char *name, gboolean daemonize, const char *pidfile)
{
    int rc;
    pid_t pid;

    if (daemonize == FALSE) {
        return;
    }

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
        crm_err("Could not lock '%s' for %s: %s " CRM_XS " rc=%d",
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

char *
crm_meta_name(const char *field)
{
    int lpc = 0;
    int max = 0;
    char *crm_name = NULL;

    CRM_CHECK(field != NULL, return NULL);
    crm_name = crm_strdup_printf(CRM_META "_%s", field);

    /* Massage the names so they can be used as shell variables */
    max = strlen(crm_name);
    for (; lpc < max; lpc++) {
        switch (crm_name[lpc]) {
            case '-':
                crm_name[lpc] = '_';
                break;
        }
    }
    return crm_name;
}

const char *
crm_meta_value(GHashTable * hash, const char *field)
{
    char *key = NULL;
    const char *value = NULL;

    key = crm_meta_name(field);
    if (key) {
        value = g_hash_table_lookup(hash, key);
        free(key);
    }

    return value;
}

#ifdef HAVE_UUID_UUID_H
#  include <uuid/uuid.h>
#endif

char *
crm_generate_uuid(void)
{
    unsigned char uuid[16];
    char *buffer = malloc(37);  /* Including NUL byte */

    uuid_generate(uuid);
    uuid_unparse(uuid, buffer);
    return buffer;
}

/*!
 * \brief Get name to be used as identifier for cluster messages
 *
 * \param[in] name  Actual system name to check
 *
 * \return Non-NULL cluster message identifier corresponding to name
 *
 * \note The Pacemaker daemons were renamed in version 2.0.0, but the old names
 *       must continue to be used as the identifier for cluster messages, so
 *       that mixed-version clusters are possible during a rolling upgrade.
 */
const char *
pcmk_message_name(const char *name)
{
    if (name == NULL) {
        return "unknown";

    } else if (!strcmp(name, "pacemaker-attrd")) {
        return "attrd";

    } else if (!strcmp(name, "pacemaker-based")) {
        return CRM_SYSTEM_CIB;

    } else if (!strcmp(name, "pacemaker-controld")) {
        return CRM_SYSTEM_CRMD;

    } else if (!strcmp(name, "pacemaker-execd")) {
        return CRM_SYSTEM_LRMD;

    } else if (!strcmp(name, "pacemaker-fenced")) {
        return "stonith-ng";

    } else if (!strcmp(name, "pacemaker-schedulerd")) {
        return CRM_SYSTEM_PENGINE;

    } else {
        return name;
    }
}

/*!
 * \brief Check whether a string represents a cluster daemon name
 *
 * \param[in] name  String to check
 *
 * \return TRUE if name is standard client name used by daemons, FALSE otherwise
 */
bool
crm_is_daemon_name(const char *name)
{
    name = pcmk_message_name(name);
    return (!strcmp(name, CRM_SYSTEM_CRMD)
            || !strcmp(name, CRM_SYSTEM_STONITHD)
            || !strcmp(name, "stonith-ng")
            || !strcmp(name, "attrd")
            || !strcmp(name, CRM_SYSTEM_CIB)
            || !strcmp(name, CRM_SYSTEM_MCP)
            || !strcmp(name, CRM_SYSTEM_DC)
            || !strcmp(name, CRM_SYSTEM_TENGINE)
            || !strcmp(name, CRM_SYSTEM_LRMD));
}

#include <md5.h>

char *
crm_md5sum(const char *buffer)
{
    int lpc = 0, len = 0;
    char *digest = NULL;
    unsigned char raw_digest[MD5_DIGEST_SIZE];

    if (buffer == NULL) {
        buffer = "";
    }
    len = strlen(buffer);

    crm_trace("Beginning digest of %d bytes", len);
    digest = malloc(2 * MD5_DIGEST_SIZE + 1);
    if(digest) {
        md5_buffer(buffer, len, raw_digest);
        for (lpc = 0; lpc < MD5_DIGEST_SIZE; lpc++) {
            sprintf(digest + (2 * lpc), "%02x", raw_digest[lpc]);
        }
        digest[(2 * MD5_DIGEST_SIZE)] = 0;
        crm_trace("Digest %s.", digest);

    } else {
        crm_err("Could not create digest");
    }
    return digest;
}

#ifdef HAVE_GNUTLS_GNUTLS_H
void
crm_gnutls_global_init(void)
{
    signal(SIGPIPE, SIG_IGN);
    gnutls_global_init();
}
#endif

/*!
 * \brief Get the local hostname
 *
 * \return Newly allocated string with name, or NULL (and set errno) on error
 */
char *
pcmk_hostname()
{
    struct utsname hostinfo;

    return (uname(&hostinfo) < 0)? NULL : strdup(hostinfo.nodename);
}

bool
pcmk_str_is_infinity(const char *s) {
    return crm_str_eq(s, CRM_INFINITY_S, TRUE) || crm_str_eq(s, CRM_PLUS_INFINITY_S, TRUE);
}

bool
pcmk_str_is_minus_infinity(const char *s) {
    return crm_str_eq(s, CRM_MINUS_INFINITY_S, TRUE);
}
