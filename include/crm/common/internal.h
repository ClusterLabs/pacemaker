/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_INTERNAL__H
#define PCMK__CRM_COMMON_INTERNAL__H

#include <stdbool.h>            // bool
#include <stdint.h>             // uint8_t, uint64_t
#include <sys/types.h>          // pid_t, uid_t, gid_t
#include <unistd.h>             // getpid()

#include <glib.h>               // guint, GList, GHashTable

#include <crm/common/agents_internal.h>
#include <crm/common/acl_internal.h>
#include <crm/common/actions_internal.h>
#include <crm/common/digest_internal.h>
#include <crm/common/flags_internal.h>
#include <crm/common/health_internal.h>
#include <crm/common/io_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/mainloop_internal.h>
#include <crm/common/memory_internal.h>
#include <crm/common/messages_internal.h>
#include <crm/common/nvpair_internal.h>
#include <crm/common/results_internal.h>
#include <crm/common/scores_internal.h>
#include <crm/common/strings_internal.h>    // pcmk__assert_asprintf()

#ifdef __cplusplus
extern "C" {
#endif

/* This says whether the current application is a Pacemaker daemon or not,
 * and is used to change default logging settings such as whether to log to
 * stderr, etc., as well as a few other details such as whether blackbox signal
 * handling is enabled.
 *
 * It is set when logging is initialized, and does not need to be set directly.
 */
extern bool pcmk__is_daemon;

// Number of elements in a statically defined array
#define PCMK__NELEM(a) ((int) (sizeof(a)/sizeof(a[0])) )

#if PCMK__ENABLE_CIBSECRETS
/* internal CIB utilities (from cib_secrets.c) */

int pcmk__substitute_secrets(const char *rsc_id, GHashTable *params);
#endif


/* internal procfs utilities (from procfs.c) */

pid_t pcmk__procfs_pid_of(const char *name);
unsigned int pcmk__procfs_num_cores(void);
int pcmk__procfs_pid2path(pid_t pid, char **path);
bool pcmk__procfs_has_pids(void);
DIR *pcmk__procfs_fd_dir(void);
void pcmk__sysrq_trigger(char t);
bool pcmk__throttle_cib_load(const char *server, float *load);
bool pcmk__throttle_load_avg(float *load);

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


// miscellaneous utilities (from utils.c)

int pcmk__compare_versions(const char *version1, const char *version2);
int pcmk__daemon_user(uid_t *uid, gid_t *gid);
char *pcmk__generate_uuid(void);
int pcmk__lookup_user(const char *name, uid_t *uid, gid_t *gid);
void pcmk__panic(const char *reason);
pid_t pcmk__locate_sbd(void);
void pcmk__sleep_ms(unsigned int ms);
guint pcmk__create_timer(guint interval_ms, GSourceFunc fn, gpointer data);
guint pcmk__timeout_ms2s(guint timeout_ms);

extern int pcmk__score_red;
extern int pcmk__score_green;
extern int pcmk__score_yellow;

static inline char *
pcmk__getpid_s(void)
{
    return pcmk__assert_asprintf("%lu", (unsigned long) getpid());
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
    return pcmk__assert_asprintf("%s-%s#%s_%u", prefix, rsc_id, op,
                                 interval_ms);
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

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_INTERNAL__H
