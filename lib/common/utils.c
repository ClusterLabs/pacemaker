/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <dlfcn.h>

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

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#ifndef PW_BUFFER_LEN
#  define PW_BUFFER_LEN		500
#endif

CRM_TRACE_INIT_DATA(common);

gboolean crm_config_error = FALSE;
gboolean crm_config_warning = FALSE;
char *crm_system_name = NULL;

int node_score_red = 0;
int node_score_green = 0;
int node_score_yellow = 0;

static struct crm_option *crm_long_options = NULL;
static const char *crm_app_description = NULL;
static char *crm_short_options = NULL;
static const char *crm_app_usage = NULL;

gboolean
check_time(const char *value)
{
    if (crm_get_msec(value) < 5000) {
        return FALSE;
    }
    return TRUE;
}

gboolean
check_timer(const char *value)
{
    if (crm_get_msec(value) < 0) {
        return FALSE;
    }
    return TRUE;
}

gboolean
check_boolean(const char *value)
{
    int tmp = FALSE;

    if (crm_str_to_boolean(value, &tmp) != 1) {
        return FALSE;
    }
    return TRUE;
}

gboolean
check_number(const char *value)
{
    errno = 0;
    if (value == NULL) {
        return FALSE;

    } else if (safe_str_eq(value, CRM_MINUS_INFINITY_S)) {

    } else if (safe_str_eq(value, CRM_INFINITY_S)) {

    } else {
        crm_int_helper(value, NULL);
    }

    if (errno != 0) {
        return FALSE;
    }
    return TRUE;
}

gboolean
check_positive_number(const char* value)
{
    if (safe_str_eq(value, CRM_INFINITY_S) || (crm_int_helper(value, NULL))) {
        return TRUE;
    }
    return FALSE;
}

gboolean
check_quorum(const char *value)
{
    if (safe_str_eq(value, "stop")) {
        return TRUE;

    } else if (safe_str_eq(value, "freeze")) {
        return TRUE;

    } else if (safe_str_eq(value, "ignore")) {
        return TRUE;

    } else if (safe_str_eq(value, "suicide")) {
        return TRUE;
    }
    return FALSE;
}

gboolean
check_script(const char *value)
{
    struct stat st;

    if(safe_str_eq(value, "/dev/null")) {
        return TRUE;
    }

    if(stat(value, &st) != 0) {
        crm_err("Script %s does not exist", value);
        return FALSE;
    }

    if(S_ISREG(st.st_mode) == 0) {
        crm_err("Script %s is not a regular file", value);
        return FALSE;
    }

    if( (st.st_mode & (S_IXUSR | S_IXGRP )) == 0) {
        crm_err("Script %s is not executable", value);
        return FALSE;
    }

    return TRUE;
}

gboolean
check_utilization(const char *value)
{
    char *end = NULL;
    long number = strtol(value, &end, 10);

    if(end && end[0] != '%') {
        return FALSE;
    } else if(number < 0) {
        return FALSE;
    }

    return TRUE;
}

void
crm_args_fini()
{
    free(crm_short_options);
    crm_short_options = NULL;
}

int
char2score(const char *score)
{
    int score_f = 0;

    if (score == NULL) {

    } else if (safe_str_eq(score, CRM_MINUS_INFINITY_S)) {
        score_f = -CRM_SCORE_INFINITY;

    } else if (safe_str_eq(score, CRM_INFINITY_S)) {
        score_f = CRM_SCORE_INFINITY;

    } else if (safe_str_eq(score, CRM_PLUS_INFINITY_S)) {
        score_f = CRM_SCORE_INFINITY;

    } else if (safe_str_eq(score, "red")) {
        score_f = node_score_red;

    } else if (safe_str_eq(score, "yellow")) {
        score_f = node_score_yellow;

    } else if (safe_str_eq(score, "green")) {
        score_f = node_score_green;

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

const char *
cluster_option(GHashTable * options, gboolean(*validate) (const char *),
               const char *name, const char *old_name, const char *def_value)
{
    const char *value = NULL;
    char *new_value = NULL;

    CRM_ASSERT(name != NULL);

    if (options) {
        value = g_hash_table_lookup(options, name);

        if ((value == NULL) && old_name) {
            value = g_hash_table_lookup(options, old_name);
            if (value != NULL) {
                crm_config_warn("Support for legacy name '%s' for cluster option '%s'"
                                " is deprecated and will be removed in a future release",
                                old_name, name);

                // Inserting copy with current name ensures we only warn once
                new_value = strdup(value);
                g_hash_table_insert(options, strdup(name), new_value);
                value = new_value;
            }
        }

        if (value && validate && (validate(value) == FALSE)) {
            crm_config_err("Resetting cluster option '%s' to default: value '%s' is invalid",
                           name, value);
            value = NULL;
        }

        if (value) {
            return value;
        }
    }

    // No value found, use default
    value = def_value;

    if (value == NULL) {
        crm_trace("No value or default provided for cluster option '%s'",
                  name);
        return NULL;
    }

    if (validate) {
        CRM_CHECK(validate(value) != FALSE,
                  crm_err("Bug: default value for cluster option '%s' is invalid", name);
                  return NULL);
    }

    crm_trace("Using default value '%s' for cluster option '%s'",
              value, name);
    if (options) {
        new_value = strdup(value);
        g_hash_table_insert(options, strdup(name), new_value);
        value = new_value;
    }
    return value;
}

const char *
get_cluster_pref(GHashTable * options, pe_cluster_option * option_list, int len, const char *name)
{
    const char *value = NULL;

    for (int lpc = 0; lpc < len; lpc++) {
        if (safe_str_eq(name, option_list[lpc].name)) {
            value = cluster_option(options,
                                   option_list[lpc].is_valid,
                                   option_list[lpc].name,
                                   option_list[lpc].alt_name,
                                   option_list[lpc].default_value);
            return value;
        }
    }
    CRM_CHECK(FALSE, crm_err("Bug: looking for unknown option '%s'", name));
    return NULL;
}

void
config_metadata(const char *name, const char *version, const char *desc_short,
                const char *desc_long, pe_cluster_option * option_list, int len)
{
    int lpc = 0;

    fprintf(stdout, "<?xml version=\"1.0\"?>"
            "<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
            "<resource-agent name=\"%s\">\n"
            "  <version>%s</version>\n"
            "  <longdesc lang=\"en\">%s</longdesc>\n"
            "  <shortdesc lang=\"en\">%s</shortdesc>\n"
            "  <parameters>\n", name, version, desc_long, desc_short);

    for (lpc = 0; lpc < len; lpc++) {
        if (option_list[lpc].description_long == NULL && option_list[lpc].description_short == NULL) {
            continue;
        }
        fprintf(stdout, "    <parameter name=\"%s\" unique=\"0\">\n"
                "      <shortdesc lang=\"en\">%s</shortdesc>\n"
                "      <content type=\"%s\" default=\"%s\"/>\n"
                "      <longdesc lang=\"en\">%s%s%s</longdesc>\n"
                "    </parameter>\n",
                option_list[lpc].name,
                option_list[lpc].description_short,
                option_list[lpc].type,
                option_list[lpc].default_value,
                option_list[lpc].description_long ? option_list[lpc].
                description_long : option_list[lpc].description_short,
                option_list[lpc].values ? "  Allowed values: " : "",
                option_list[lpc].values ? option_list[lpc].values : "");
    }
    fprintf(stdout, "  </parameters>\n</resource-agent>\n");
}

void
verify_all_options(GHashTable * options, pe_cluster_option * option_list, int len)
{
    int lpc = 0;

    for (lpc = 0; lpc < len; lpc++) {
        cluster_option(options,
                       option_list[lpc].is_valid,
                       option_list[lpc].name,
                       option_list[lpc].alt_name, option_list[lpc].default_value);
    }
}

char *
generate_hash_key(const char *crm_msg_reference, const char *sys)
{
    char *hash_key = crm_concat(sys ? sys : "none", crm_msg_reference, '_');

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

static int
crm_version_helper(const char *text, char **end_text)
{
    int atoi_result = -1;

    CRM_ASSERT(end_text != NULL);

    errno = 0;

    if (text != NULL && text[0] != 0) {
        atoi_result = (int)strtol(text, end_text, 10);

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
    char *ver1_copy = NULL, *ver2_copy = NULL;
    char *rest1 = NULL, *rest2 = NULL;

    if (version1 == NULL && version2 == NULL) {
        return 0;
    } else if (version1 == NULL) {
        return -1;
    } else if (version2 == NULL) {
        return 1;
    }

    ver1_copy = strdup(version1);
    ver2_copy = strdup(version2);
    rest1 = ver1_copy;
    rest2 = ver2_copy;

    while (1) {
        int digit1 = 0;
        int digit2 = 0;

        lpc++;

        if (rest1 == rest2) {
            break;
        }

        if (rest1 != NULL) {
            digit1 = crm_version_helper(rest1, &rest1);
        }

        if (rest2 != NULL) {
            digit2 = crm_version_helper(rest2, &rest2);
        }

        if (digit1 < digit2) {
            rc = -1;
            break;

        } else if (digit1 > digit2) {
            rc = 1;
            break;
        }

        if (rest1 != NULL && rest1[0] == '.') {
            rest1++;
        }
        if (rest1 != NULL && rest1[0] == 0) {
            rest1 = NULL;
        }

        if (rest2 != NULL && rest2[0] == '.') {
            rest2++;
        }
        if (rest2 != NULL && rest2[0] == 0) {
            rest2 = NULL;
        }
    }

    free(ver1_copy);
    free(ver2_copy);

    if (rc == 0) {
        crm_trace("%s == %s (%d)", version1, version2, lpc);
    } else if (rc < 0) {
        crm_trace("%s < %s (%d)", version1, version2, lpc);
    } else if (rc > 0) {
        crm_trace("%s > %s (%d)", version1, version2, lpc);
    }

    return rc;
}

gboolean do_stderr = FALSE;

#ifndef NUMCHARS
#  define	NUMCHARS	"0123456789."
#endif

#ifndef WHITESPACE
#  define	WHITESPACE	" \t\n\r\f"
#endif

guint
crm_parse_interval_spec(const char *input)
{
    long long msec = 0;

    if (input == NULL) {
        return 0;

    } else if (input[0] != 'P') {
        long long tmp = crm_get_msec(input);

        if(tmp > 0) {
            msec = tmp;
        }

    } else {
        crm_time_t *period_s = crm_time_parse_duration(input);

        msec = 1000 * crm_time_get_seconds(period_s);
        crm_time_free(period_s);
    }

    return (msec <= 0)? 0 : ((msec >= G_MAXUINT)? G_MAXUINT : (guint) msec);
}

long long
crm_get_msec(const char *input)
{
    const char *cp = input;
    const char *units;
    long long multiplier = 1000;
    long long divisor = 1;
    long long msec = -1;
    char *end_text = NULL;

    /* double dret; */

    if (input == NULL) {
        return msec;
    }

    cp += strspn(cp, WHITESPACE);
    units = cp + strspn(cp, NUMCHARS);
    units += strspn(units, WHITESPACE);

    if (strchr(NUMCHARS, *cp) == NULL) {
        return msec;
    }

    if (strncasecmp(units, "ms", 2) == 0 || strncasecmp(units, "msec", 4) == 0) {
        multiplier = 1;
        divisor = 1;
    } else if (strncasecmp(units, "us", 2) == 0 || strncasecmp(units, "usec", 4) == 0) {
        multiplier = 1;
        divisor = 1000;
    } else if (strncasecmp(units, "s", 1) == 0 || strncasecmp(units, "sec", 3) == 0) {
        multiplier = 1000;
        divisor = 1;
    } else if (strncasecmp(units, "m", 1) == 0 || strncasecmp(units, "min", 3) == 0) {
        multiplier = 60 * 1000;
        divisor = 1;
    } else if (strncasecmp(units, "h", 1) == 0 || strncasecmp(units, "hr", 2) == 0) {
        multiplier = 60 * 60 * 1000;
        divisor = 1;
    } else if (*units != EOS && *units != '\n' && *units != '\r') {
        return msec;
    }

    msec = crm_int_helper(cp, &end_text);
    if (msec > LLONG_MAX/multiplier) {
        /* arithmetics overflow while multiplier/divisor mutually exclusive */
        return LLONG_MAX;
    }
    msec *= multiplier;
    msec /= divisor;
    /* dret += 0.5; */
    /* msec = (long long)dret; */
    return msec;
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
    long pid;
    const char *devnull = "/dev/null";

    if (daemonize == FALSE) {
        return;
    }

    /* Check before we even try... */
    rc = crm_pidfile_inuse(pidfile, 1, name);
    if(rc < pcmk_ok && rc != -ENOENT) {
        pid = crm_read_pidfile(pidfile);
        crm_err("%s: already running [pid %ld in %s]", name, pid, pidfile);
        printf("%s: already running [pid %ld in %s]\n", name, pid, pidfile);
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

    rc = crm_lock_pidfile(pidfile, name);
    if(rc < pcmk_ok) {
        crm_err("Could not lock '%s' for %s: %s (%d)", pidfile, name, pcmk_strerror(rc), rc);
        printf("Could not lock '%s' for %s: %s (%d)\n", pidfile, name, pcmk_strerror(rc), rc);
        crm_exit(CRM_EX_ERROR);
    }

    umask(S_IWGRP | S_IWOTH | S_IROTH);

    close(STDIN_FILENO);
    (void)open(devnull, O_RDONLY);      /* Stdin:  fd 0 */
    close(STDOUT_FILENO);
    (void)open(devnull, O_WRONLY);      /* Stdout: fd 1 */
    close(STDERR_FILENO);
    (void)open(devnull, O_WRONLY);      /* Stderr: fd 2 */
}

char *
crm_meta_name(const char *field)
{
    int lpc = 0;
    int max = 0;
    char *crm_name = NULL;

    CRM_CHECK(field != NULL, return NULL);
    crm_name = crm_concat(CRM_META, field, '_');

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

static struct option *
crm_create_long_opts(struct crm_option *long_options)
{
    struct option *long_opts = NULL;

#ifdef HAVE_GETOPT_H
    int index = 0, lpc = 0;

    /*
     * A previous, possibly poor, choice of '?' as the short form of --help
     * means that getopt_long() returns '?' for both --help and for "unknown option"
     *
     * This dummy entry allows us to differentiate between the two in crm_get_option()
     * and exit with the correct error code
     */
    long_opts = realloc_safe(long_opts, (index + 1) * sizeof(struct option));
    long_opts[index].name = "__dummmy__";
    long_opts[index].has_arg = 0;
    long_opts[index].flag = 0;
    long_opts[index].val = '_';
    index++;

    for (lpc = 0; long_options[lpc].name != NULL; lpc++) {
        if (long_options[lpc].name[0] == '-') {
            continue;
        }

        long_opts = realloc_safe(long_opts, (index + 1) * sizeof(struct option));
        /*fprintf(stderr, "Creating %d %s = %c\n", index,
         * long_options[lpc].name, long_options[lpc].val);      */
        long_opts[index].name = long_options[lpc].name;
        long_opts[index].has_arg = long_options[lpc].has_arg;
        long_opts[index].flag = long_options[lpc].flag;
        long_opts[index].val = long_options[lpc].val;
        index++;
    }

    /* Now create the list terminator */
    long_opts = realloc_safe(long_opts, (index + 1) * sizeof(struct option));
    long_opts[index].name = NULL;
    long_opts[index].has_arg = 0;
    long_opts[index].flag = 0;
    long_opts[index].val = 0;
#endif

    return long_opts;
}

void
crm_set_options(const char *short_options, const char *app_usage, struct crm_option *long_options,
                const char *app_desc)
{
    if (short_options) {
        crm_short_options = strdup(short_options);

    } else if (long_options) {
        int lpc = 0;
        int opt_string_len = 0;
        char *local_short_options = NULL;

        for (lpc = 0; long_options[lpc].name != NULL; lpc++) {
            if (long_options[lpc].val && long_options[lpc].val != '-' && long_options[lpc].val < UCHAR_MAX) {
                local_short_options = realloc_safe(local_short_options, opt_string_len + 4);
                local_short_options[opt_string_len++] = long_options[lpc].val;
                /* getopt(3) says: Two colons mean an option takes an optional arg; */
                if (long_options[lpc].has_arg == optional_argument) {
                    local_short_options[opt_string_len++] = ':';
                }
                if (long_options[lpc].has_arg >= required_argument) {
                    local_short_options[opt_string_len++] = ':';
                }
                local_short_options[opt_string_len] = 0;
            }
        }
        crm_short_options = local_short_options;
        crm_trace("Generated short option string: '%s'", local_short_options);
    }

    if (long_options) {
        crm_long_options = long_options;
    }
    if (app_desc) {
        crm_app_description = app_desc;
    }
    if (app_usage) {
        crm_app_usage = app_usage;
    }
}

int
crm_get_option(int argc, char **argv, int *index)
{
    return crm_get_option_long(argc, argv, index, NULL);
}

int
crm_get_option_long(int argc, char **argv, int *index, const char **longname)
{
#ifdef HAVE_GETOPT_H
    static struct option *long_opts = NULL;

    if (long_opts == NULL && crm_long_options) {
        long_opts = crm_create_long_opts(crm_long_options);
    }

    *index = 0;
    if (long_opts) {
        int flag = getopt_long(argc, argv, crm_short_options, long_opts, index);

        switch (flag) {
            case 0:
                if (long_opts[*index].val) {
                    return long_opts[*index].val;
                } else if (longname) {
                    *longname = long_opts[*index].name;
                } else {
                    crm_notice("Unhandled option --%s", long_opts[*index].name);
                    return flag;
                }
            case -1:           /* End of option processing */
                break;
            case ':':
                crm_trace("Missing argument");
                crm_help('?', CRM_EX_USAGE);
                break;
            case '?':
                crm_help('?', (*index? CRM_EX_OK : CRM_EX_USAGE));
                break;
        }
        return flag;
    }
#endif

    if (crm_short_options) {
        return getopt(argc, argv, crm_short_options);
    }

    return -1;
}

crm_exit_t
crm_help(char cmd, crm_exit_t exit_code)
{
    int i = 0;
    FILE *stream = (exit_code ? stderr : stdout);

    if (cmd == 'v' || cmd == '$') {
        fprintf(stream, "Pacemaker %s\n", PACEMAKER_VERSION);
        fprintf(stream, "Written by Andrew Beekhof\n");
        goto out;
    }

    if (cmd == '!') {
        fprintf(stream, "Pacemaker %s (Build: %s): %s\n", PACEMAKER_VERSION, BUILD_VERSION, CRM_FEATURES);
        goto out;
    }

    fprintf(stream, "%s - %s\n", crm_system_name, crm_app_description);

    if (crm_app_usage) {
        fprintf(stream, "Usage: %s %s\n", crm_system_name, crm_app_usage);
    }

    if (crm_long_options) {
        fprintf(stream, "Options:\n");
        for (i = 0; crm_long_options[i].name != NULL; i++) {
            if (crm_long_options[i].flags & pcmk_option_hidden) {

            } else if (crm_long_options[i].flags & pcmk_option_paragraph) {
                fprintf(stream, "%s\n\n", crm_long_options[i].desc);

            } else if (crm_long_options[i].flags & pcmk_option_example) {
                fprintf(stream, "\t#%s\n\n", crm_long_options[i].desc);

            } else if (crm_long_options[i].val == '-' && crm_long_options[i].desc) {
                fprintf(stream, "%s\n", crm_long_options[i].desc);

            } else {
                /* is val printable as char ? */
                if (crm_long_options[i].val && crm_long_options[i].val <= UCHAR_MAX) {
                    fprintf(stream, " -%c,", crm_long_options[i].val);
                } else {
                    fputs("    ", stream);
                }
                fprintf(stream, " --%s%s\t%s\n", crm_long_options[i].name,
                        crm_long_options[i].has_arg == optional_argument ? "[=value]" :
                        crm_long_options[i].has_arg == required_argument ? "=value" : "",
                        crm_long_options[i].desc ? crm_long_options[i].desc : "");
            }
        }

    } else if (crm_short_options) {
        fprintf(stream, "Usage: %s - %s\n", crm_system_name, crm_app_description);
        for (i = 0; crm_short_options[i] != 0; i++) {
            int has_arg = no_argument /* 0 */;

            if (crm_short_options[i + 1] == ':') {
                if (crm_short_options[i + 2] == ':')
                    has_arg = optional_argument /* 2 */;
                else
                    has_arg = required_argument /* 1 */;
            }

            fprintf(stream, " -%c %s\n", crm_short_options[i],
                    has_arg == optional_argument ? "[value]" :
                    has_arg == required_argument ? "{value}" : "");
            i += has_arg;
        }
    }

    fprintf(stream, "\nReport bugs to %s\n", PACKAGE_BUGREPORT);

  out:
    return crm_exit(exit_code);
}

void cib_ipc_servers_init(qb_ipcs_service_t **ipcs_ro,
        qb_ipcs_service_t **ipcs_rw,
        qb_ipcs_service_t **ipcs_shm,
        struct qb_ipcs_service_handlers *ro_cb,
        struct qb_ipcs_service_handlers *rw_cb)
{
    *ipcs_ro = mainloop_add_ipc_server(cib_channel_ro, QB_IPC_NATIVE, ro_cb);
    *ipcs_rw = mainloop_add_ipc_server(cib_channel_rw, QB_IPC_NATIVE, rw_cb);
    *ipcs_shm = mainloop_add_ipc_server(cib_channel_shm, QB_IPC_SHM, rw_cb);

    if (*ipcs_ro == NULL || *ipcs_rw == NULL || *ipcs_shm == NULL) {
        crm_err("Failed to create the CIB manager: exiting and inhibiting respawn");
        crm_warn("Verify pacemaker and pacemaker_remote are not both enabled");
        crm_exit(CRM_EX_FATAL);
    }
}

void cib_ipc_servers_destroy(qb_ipcs_service_t *ipcs_ro,
        qb_ipcs_service_t *ipcs_rw,
        qb_ipcs_service_t *ipcs_shm)
{
    qb_ipcs_destroy(ipcs_ro);
    qb_ipcs_destroy(ipcs_rw);
    qb_ipcs_destroy(ipcs_shm);
}

qb_ipcs_service_t *
crmd_ipc_server_init(struct qb_ipcs_service_handlers *cb)
{
    return mainloop_add_ipc_server(CRM_SYSTEM_CRMD, QB_IPC_NATIVE, cb);
}

void
attrd_ipc_server_init(qb_ipcs_service_t **ipcs, struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server(T_ATTRD, QB_IPC_NATIVE, cb);

    if (*ipcs == NULL) {
        crm_err("Failed to create pacemaker-attrd server: exiting and inhibiting respawn");
        crm_warn("Verify pacemaker and pacemaker_remote are not both enabled.");
        crm_exit(CRM_EX_FATAL);
    }
}

void
stonith_ipc_server_init(qb_ipcs_service_t **ipcs, struct qb_ipcs_service_handlers *cb)
{
    *ipcs = mainloop_add_ipc_server("stonith-ng", QB_IPC_NATIVE, cb);

    if (*ipcs == NULL) {
        crm_err("Failed to create fencer: exiting and inhibiting respawn.");
        crm_warn("Verify pacemaker and pacemaker_remote are not both enabled.");
        crm_exit(CRM_EX_FATAL);
    }
}

bool
pcmk_acl_required(const char *user) 
{
#if ENABLE_ACL
    if(user == NULL || strlen(user) == 0) {
        crm_trace("no user set");
        return FALSE;

    } else if (strcmp(user, CRM_DAEMON_USER) == 0) {
        return FALSE;

    } else if (strcmp(user, "root") == 0) {
        return FALSE;
    }
    crm_trace("acls required for %s", user);
    return TRUE;
#else
    crm_trace("acls not supported");
    return FALSE;
#endif
}

#if ENABLE_ACL
char *
uid2username(uid_t uid)
{
    struct passwd *pwent = getpwuid(uid);

    if (pwent == NULL) {
        crm_perror(LOG_ERR, "Cannot get password entry of uid: %d", uid);
        return NULL;

    } else {
        return strdup(pwent->pw_name);
    }
}

const char *
crm_acl_get_set_user(xmlNode * request, const char *field, const char *peer_user)
{
    /* field is only checked for backwards compatibility */
    static const char *effective_user = NULL;
    const char *requested_user = NULL;
    const char *user = NULL;

    if(effective_user == NULL) {
        effective_user = uid2username(geteuid());
    }

    requested_user = crm_element_value(request, XML_ACL_TAG_USER);
    if(requested_user == NULL) {
        requested_user = crm_element_value(request, field);
    }

    if (is_privileged(effective_user) == FALSE) {
        /* We're not running as a privileged user, set or overwrite any existing value for $XML_ACL_TAG_USER */
        user = effective_user;

    } else if(peer_user == NULL && requested_user == NULL) {
        /* No user known or requested, use 'effective_user' and make sure one is set for the request */
        user = effective_user;

    } else if(peer_user == NULL) {
        /* No user known, trusting 'requested_user' */
        user = requested_user;

    } else if (is_privileged(peer_user) == FALSE) {
        /* The peer is not a privileged user, set or overwrite any existing value for $XML_ACL_TAG_USER */
        user = peer_user;

    } else if (requested_user == NULL) {
        /* Even if we're privileged, make sure there is always a value set */
        user = peer_user;

    } else {
        /* Legal delegation to 'requested_user' */
        user = requested_user;
    }

    // This requires pointer comparison, not string comparison
    if(user != crm_element_value(request, XML_ACL_TAG_USER)) {
        crm_xml_add(request, XML_ACL_TAG_USER, user);
    }

    if(field != NULL && user != crm_element_value(request, field)) {
        crm_xml_add(request, field, user);
    }

    return requested_user;
}

void
determine_request_user(const char *user, xmlNode * request, const char *field)
{
    /* Get our internal validation out of the way first */
    CRM_CHECK(user != NULL && request != NULL && field != NULL, return);

    /* If our peer is a privileged user, we might be doing something on behalf of someone else */
    if (is_privileged(user) == FALSE) {
        /* We're not a privileged user, set or overwrite any existing value for $field */
        crm_xml_replace(request, field, user);

    } else if (crm_element_value(request, field) == NULL) {
        /* Even if we're privileged, make sure there is always a value set */
        crm_xml_replace(request, field, user);

/*  } else { Legal delegation */
    }

    crm_trace("Processing msg as user '%s'", crm_element_value(request, field));
}
#endif

void *
find_library_function(void **handle, const char *lib, const char *fn, gboolean fatal)
{
    char *error;
    void *a_function;

    if (*handle == NULL) {
        *handle = dlopen(lib, RTLD_LAZY);
    }

    if (!(*handle)) {
        crm_err("%sCould not open %s: %s", fatal ? "Fatal: " : "", lib, dlerror());
        if (fatal) {
            crm_exit(CRM_EX_FATAL);
        }
        return NULL;
    }

    a_function = dlsym(*handle, fn);
    if (a_function == NULL) {
        error = dlerror();
        crm_err("%sCould not find %s in %s: %s", fatal ? "Fatal: " : "", fn, lib, error);
        if (fatal) {
            crm_exit(CRM_EX_FATAL);
        }
    }

    return a_function;
}

void *
convert_const_pointer(const void *ptr)
{
    /* Worst function ever */
    return (void *)ptr;
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
 * \brief Check whether a string represents a cluster daemon name
 *
 * \param[in] name  String to check
 *
 * \return TRUE if name is standard client name used by daemons, FALSE otherwise
 */
bool
crm_is_daemon_name(const char *name)
{
    return (name &&
            (!strcmp(name, CRM_SYSTEM_CRMD)
            || !strcmp(name, CRM_SYSTEM_STONITHD)
            || !strcmp(name, T_ATTRD)
            || !strcmp(name, CRM_SYSTEM_CIB)
            || !strcmp(name, CRM_SYSTEM_MCP)
            || !strcmp(name, CRM_SYSTEM_DC)
            || !strcmp(name, CRM_SYSTEM_TENGINE)
            || !strcmp(name, CRM_SYSTEM_LRMD)));
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

char *
crm_generate_ra_key(const char *standard, const char *provider, const char *type)
{
    if (!standard && !provider && !type) {
        return NULL;
    }

    return crm_strdup_printf("%s%s%s:%s",
                             (standard? standard : ""),
                             (provider? ":" : ""), (provider? provider : ""),
                             (type? type : ""));
}

/*!
 * \brief Check whether a resource standard requires a provider to be specified
 *
 * \param[in] standard  Standard name
 *
 * \return TRUE if standard requires a provider, FALSE otherwise
 */
bool
crm_provider_required(const char *standard)
{
    CRM_CHECK(standard != NULL, return FALSE);

    /* @TODO
     * - this should probably be case-sensitive, but isn't,
     *   for backward compatibility
     * - it might be nice to keep standards' capabilities (supports provider,
     *   can be promotable, etc.) as structured data somewhere
     */
    if (!strcasecmp(standard, PCMK_RESOURCE_CLASS_OCF)) {
        return TRUE;
    }
    return FALSE;
}

/*!
 * \brief Parse a "standard[:provider]:type" agent specification
 *
 * \param[in]  spec      Agent specification
 * \param[out] standard  Newly allocated memory containing agent standard (or NULL)
 * \param[out] provider  Newly allocated memory containing agent provider (or NULL)
 * \param[put] type      Newly allocated memory containing agent type (or NULL)
 *
 * \return pcmk_ok if the string could be parsed, -EINVAL otherwise
 *
 * \note It is acceptable for the type to contain a ':' if the standard supports
 *       that. For example, systemd supports the form "systemd:UNIT@A:B".
 * \note It is the caller's responsibility to free the returned values.
 */
int
crm_parse_agent_spec(const char *spec, char **standard, char **provider,
                     char **type)
{
    char *colon;

    CRM_CHECK(spec && standard && provider && type, return -EINVAL);
    *standard = NULL;
    *provider = NULL;
    *type = NULL;

    colon = strchr(spec, ':');
    if ((colon == NULL) || (colon == spec)) {
        return -EINVAL;
    }

    *standard = strndup(spec, colon - spec);
    spec = colon + 1;

    if (crm_provider_required(*standard)) {
        colon = strchr(spec, ':');
        if ((colon == NULL) || (colon == spec)) {
            free(*standard);
            return -EINVAL;
        }
        *provider = strndup(spec, colon - spec);
        spec = colon + 1;
    }

    if (*spec == '\0') {
        free(*standard);
        free(*provider);
        return -EINVAL;
    }

    *type = strdup(spec);
    return pcmk_ok;
}
