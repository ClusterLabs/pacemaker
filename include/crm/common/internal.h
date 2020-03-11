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

#include <glib.h>       /* for gboolean */
#include <dirent.h>     /* for struct dirent */
#include <unistd.h>     /* for getpid() */
#include <stdbool.h>    /* for bool */
#include <sys/types.h>  // uid_t, gid_t, pid_t

#include <crm/common/logging.h>


#if SUPPORT_CIBSECRETS
// Internal CIB utilities (from cib_secrets.c) */

int pcmk__substitute_secrets(const char *rsc_id, GHashTable *params);
#endif


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

bool pcmk__daemon_can_write(const char *dir, const char *file);
void pcmk__sync_directory(const char *name);

int pcmk__file_contents(const char *filename, char **contents);
int pcmk__write_sync(int fd, const char *contents);
int pcmk__set_nonblocking(int fd);
const char *pcmk__get_tmpdir(void);

void pcmk__close_fds_in_child(bool);


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

char *pcmk__op_key(const char *rsc_id, const char *op_type, guint interval_ms);
char *generate_notify_key(const char *rsc_id, const char *notify_type,
                          const char *op_type);
char *generate_transition_key(int transition_id, int action_id, int target_rc,
                              const char *node);
void filter_action_parameters(xmlNode *param_set, const char *version);


// miscellaneous utilities (from utils.c)

const char *pcmk_message_name(const char *name);


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

static inline char *
crm_concat(const char *prefix, const char *suffix, char join)
{
    CRM_ASSERT(prefix && suffix);
    return crm_strdup_printf("%s%c%s", prefix, join, suffix);
}

static inline int
crm_strlen_zero(const char *s)
{
    return !s || *s == '\0';
}

static inline char *
crm_getpid_s()
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

#define CRM_FAIL_COUNT_PREFIX   "fail-count"
#define CRM_LAST_FAILURE_PREFIX "last-failure"

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
crm_fail_attr_name(const char *prefix, const char *rsc_id, const char *op,
                   guint interval_ms)
{
    CRM_CHECK(prefix && rsc_id && op, return NULL);
    return crm_strdup_printf("%s-%s#%s_%u", prefix, rsc_id, op, interval_ms);
}

static inline char *
crm_failcount_name(const char *rsc_id, const char *op, guint interval_ms)
{
    return crm_fail_attr_name(CRM_FAIL_COUNT_PREFIX, rsc_id, op, interval_ms);
}

static inline char *
crm_lastfailure_name(const char *rsc_id, const char *op, guint interval_ms)
{
    return crm_fail_attr_name(CRM_LAST_FAILURE_PREFIX, rsc_id, op, interval_ms);
}

#endif /* CRM_COMMON_INTERNAL__H */
