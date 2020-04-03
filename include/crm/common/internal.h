/*
 * Copyright 2015-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_COMMON_INTERNAL__H
#define CRM_COMMON_INTERNAL__H

#include <unistd.h>             // getpid()
#include <stdbool.h>            // bool
#include <string.h>             // strcmp()
#include <sys/types.h>          // uid_t, gid_t, pid_t

#include <glib.h>               // guint, GList, GHashTable
#include <libxml/tree.h>        // xmlNode

#include <crm/common/util.h>    // crm_strdup_printf()
#include <crm/common/mainloop.h> // mainloop_io_t, struct ipc_client_callbacks

// Internal ACL-related utilities (from acl.c)

char *pcmk__uid2username(uid_t uid);
const char *pcmk__update_acl_user(xmlNode *request, const char *field,
                                  const char *peer_user);

#if ENABLE_ACL
#  include <string.h>
static inline bool
pcmk__is_privileged(const char *user)
{
    return user && (!strcmp(user, CRM_DAEMON_USER) || !strcmp(user, "root"));
}
#endif


#if SUPPORT_CIBSECRETS
// Internal CIB utilities (from cib_secrets.c) */

int pcmk__substitute_secrets(const char *rsc_id, GHashTable *params);
#endif


/* internal digest-related utilities (from digest.c) */

bool pcmk__verify_digest(xmlNode *input, const char *expected);


/* internal I/O utilities (from io.c) */

int pcmk__real_path(const char *path, char **resolved_path);

char *pcmk__series_filename(const char *directory, const char *series,
                            int sequence, bool bzip);
int pcmk__read_series_sequence(const char *directory, const char *series,
                               unsigned int *seq);
void pcmk__write_series_sequence(const char *directory, const char *series,
                                 unsigned int sequence, int max);
int pcmk__chown_series_sequence(const char *directory, const char *series,
                                uid_t uid, gid_t gid);

int pcmk__build_path(const char *path_c, mode_t mode);
bool pcmk__daemon_can_write(const char *dir, const char *file);
void pcmk__sync_directory(const char *name);

int pcmk__file_contents(const char *filename, char **contents);
int pcmk__write_sync(int fd, const char *contents);
int pcmk__set_nonblocking(int fd);
const char *pcmk__get_tmpdir(void);

void pcmk__close_fds_in_child(bool);

/*!
 * \internal
 * \brief Open /dev/null to consume next available file descriptor
 *
 * Open /dev/null, disregarding the result. This is intended when daemonizing to
 * be able to null stdin, stdout, and stderr.
 *
 * \param[in] flags  O_RDONLY (stdin) or O_WRONLY (stdout and stderr)
 */
static inline void
pcmk__open_devnull(int flags)
{
    // Static analysis clutter
    // cppcheck-suppress leakReturnValNotUsed
    (void) open("/dev/null", flags);
}


/* internal logging utilities */

#  define pcmk__config_err(fmt...) do {     \
        crm_config_error = TRUE;            \
        crm_err(fmt);                       \
    } while (0)

#  define pcmk__config_warn(fmt...) do {    \
        crm_config_warning = TRUE;          \
        crm_warn(fmt);                      \
    } while (0)

/*!
 * \internal
 * \brief Execute code depending on whether message would be logged
 *
 * This is similar to do_crm_log_unlikely() except instead of logging, it either
 * continues past this statement or executes else_action depending on whether a
 * message of the given severity would be logged or not. This allows whole
 * blocks of code to be skipped if tracing or debugging is turned off.
 *
 * \param[in] level        Severity at which to continue past this statement
 * \param[in] else_action  Code block to execute if severity would not be logged
 *
 * \note else_action must not contain a break or continue statement
 */
#  define pcmk__log_else(level, else_action) do {                           \
        static struct qb_log_callsite *trace_cs = NULL;                     \
                                                                            \
        if (trace_cs == NULL) {                                             \
            trace_cs = qb_log_callsite_get(__func__, __FILE__, "log_else",  \
                                           level, __LINE__, 0);             \
        }                                                                   \
        if (!crm_is_callsite_active(trace_cs, level, 0)) {                  \
            else_action;                                                    \
        }                                                                   \
    } while(0)


/* internal main loop utilities (from mainloop.c) */

int pcmk__add_mainloop_ipc(crm_ipc_t *ipc, int priority, void *userdata,
                           struct ipc_client_callbacks *callbacks,
                           mainloop_io_t **source);


/* internal procfs utilities (from procfs.c) */

pid_t pcmk__procfs_pid_of(const char *name);
unsigned int pcmk__procfs_num_cores(void);


/* internal XML schema functions (from xml.c) */

void crm_schema_init(void);
void crm_schema_cleanup(void);


/* internal functions related to process IDs (from pid.c) */

/*!
 * \internal
 * \brief Check whether process exists (by PID and optionally executable path)
 *
 * \param[in] pid     PID of process to check
 * \param[in] daemon  If not NULL, path component to match with procfs entry
 *
 * \return Standard Pacemaker return code
 * \note Particular return codes of interest include pcmk_rc_ok for alive,
 *       ESRCH for process is not alive (verified by kill and/or executable path
 *       match), EACCES for caller unable or not allowed to check. A result of
 *       "alive" is less reliable when \p daemon is not provided or procfs is
 *       not available, since there is no guarantee that the PID has not been
 *       recycled for another process.
 * \note This function cannot be used to verify \e authenticity of the process.
 */
int pcmk__pid_active(pid_t pid, const char *daemon);

int pcmk__read_pidfile(const char *filename, pid_t *pid);
int pcmk__pidfile_matches(const char *filename, pid_t expected_pid,
                          const char *expected_name, pid_t *pid);
int pcmk__lock_pidfile(const char *filename, const char *name);


/* interal functions related to resource operations (from operations.c) */

// printf-style format to create operation ID from resource, action, interval
#define PCMK__OP_FMT "%s_%s_%u"

char *pcmk__op_key(const char *rsc_id, const char *op_type, guint interval_ms);
char *pcmk__notify_key(const char *rsc_id, const char *notify_type,
                       const char *op_type);
char *pcmk__transition_key(int transition_id, int action_id, int target_rc,
                           const char *node);
void pcmk__filter_op_for_digest(xmlNode *param_set);


// miscellaneous utilities (from utils.c)

const char *pcmk_message_name(const char *name);

extern int pcmk__score_red;
extern int pcmk__score_green;
extern int pcmk__score_yellow;


/* internal generic string functions (from strings.c) */

int pcmk__guint_from_hash(GHashTable *table, const char *key, guint default_val,
                          guint *result);
bool pcmk__starts_with(const char *str, const char *prefix);
bool pcmk__ends_with(const char *s, const char *match);
bool pcmk__ends_with_ext(const char *s, const char *match);
char *pcmk__add_word(char *list, const char *word);
int pcmk__compress(const char *data, unsigned int length, unsigned int max,
                   char **result, unsigned int *result_len);

/* Correctly displaying singular or plural is complicated; consider "1 node has"
 * vs. "2 nodes have". A flexible solution is to pluralize entire strings, e.g.
 *
 * if (a == 1) {
 *     crm_info("singular message"):
 * } else {
 *     crm_info("plural message");
 * }
 *
 * though even that's not sufficient for all languages besides English (if we
 * ever desire to do translations of output and log messages). But the following
 * convenience macros are "good enough" and more concise for many cases.
 */

/* Example:
 * crm_info("Found %d %s", nentries,
 *          pcmk__plural_alt(nentries, "entry", "entries"));
 */
#define pcmk__plural_alt(i, s1, s2) (((i) == 1)? (s1) : (s2))

// Example: crm_info("Found %d node%s", nnodes, pcmk__plural_s(nnodes));
#define pcmk__plural_s(i) pcmk__plural_alt(i, "", "s")

static inline int
pcmk__str_empty(const char *s)
{
    return (s == NULL) || (s[0] == '\0');
}

static inline char *
pcmk__getpid_s(void)
{
    return crm_strdup_printf("%lu", (unsigned long) getpid());
}

// More efficient than g_list_length(list) == 1
static inline bool
pcmk__list_of_1(GList *list)
{
    return list && (list->next == NULL);
}

// More efficient than g_list_length(list) > 1
static inline bool
pcmk__list_of_multiple(GList *list)
{
    return list && (list->next != NULL);
}

/* convenience functions for failure-related node attributes */

#define PCMK__FAIL_COUNT_PREFIX   "fail-count"
#define PCMK__LAST_FAILURE_PREFIX "last-failure"

/*!
 * \internal
 * \brief Generate a failure-related node attribute name for a resource
 *
 * \param[in] prefix       Start of attribute name
 * \param[in] rsc_id       Resource name
 * \param[in] op           Operation name
 * \param[in] interval_ms  Operation interval
 *
 * \return Newly allocated string with attribute name
 *
 * \note Failure attributes are named like PREFIX-RSC#OP_INTERVAL (for example,
 *       "fail-count-myrsc#monitor_30000"). The '#' is used because it is not
 *       a valid character in a resource ID, to reliably distinguish where the
 *       operation name begins. The '_' is used simply to be more comparable to
 *       action labels like "myrsc_monitor_30000".
 */
static inline char *
pcmk__fail_attr_name(const char *prefix, const char *rsc_id, const char *op,
                   guint interval_ms)
{
    CRM_CHECK(prefix && rsc_id && op, return NULL);
    return crm_strdup_printf("%s-%s#%s_%u", prefix, rsc_id, op, interval_ms);
}

static inline char *
pcmk__failcount_name(const char *rsc_id, const char *op, guint interval_ms)
{
    return pcmk__fail_attr_name(PCMK__FAIL_COUNT_PREFIX, rsc_id, op,
                                interval_ms);
}

static inline char *
pcmk__lastfailure_name(const char *rsc_id, const char *op, guint interval_ms)
{
    return pcmk__fail_attr_name(PCMK__LAST_FAILURE_PREFIX, rsc_id, op,
                                interval_ms);
}

#endif /* CRM_COMMON_INTERNAL__H */
