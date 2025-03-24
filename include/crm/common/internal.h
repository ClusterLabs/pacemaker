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

#include <pwd.h>                // struct passwd
#include <unistd.h>             // getpid()
#include <stdbool.h>            // bool
#include <stdint.h>             // uint8_t, uint64_t
#include <sys/types.h>          // pid_t, uid_t, gid_t
#include <inttypes.h>           // PRIu64

#include <glib.h>               // guint, GList, GHashTable
#include <libxml/tree.h>        // xmlNode

#include <crm/common/logging.h>  // do_crm_log_unlikely(), etc.
#include <crm/common/mainloop.h> // mainloop_io_t, struct ipc_client_callbacks
#include <crm/common/actions_internal.h>
#include <crm/common/digest_internal.h>
#include <crm/common/health_internal.h>
#include <crm/common/io_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/results_internal.h>
#include <crm/common/messages_internal.h>
#include <crm/common/nvpair_internal.h>
#include <crm/common/scores_internal.h>
#include <crm/common/strings_internal.h>    // pcmk__assert_asprintf()
#include <crm/common/acl_internal.h>

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


/* internal main loop utilities (from mainloop.c) */

int pcmk__add_mainloop_ipc(crm_ipc_t *ipc, int priority, void *userdata,
                           const struct ipc_client_callbacks *callbacks,
                           mainloop_io_t **source);
guint pcmk__mainloop_timer_get_period(const mainloop_timer_t *timer);


/* internal name/value utilities (from nvpair.c) */

int pcmk__scan_nvpair(const gchar *input, gchar **name, gchar **value);
char *pcmk__format_nvpair(const char *name, const char *value,
                          const char *units);

/* internal procfs utilities (from procfs.c) */

pid_t pcmk__procfs_pid_of(const char *name);
unsigned int pcmk__procfs_num_cores(void);
int pcmk__procfs_pid2path(pid_t pid, char path[], size_t path_size);
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

int pcmk__read_pidfile(const char *filename, pid_t *pid);
int pcmk__pidfile_matches(const char *filename, pid_t expected_pid,
                          const char *expected_name, pid_t *pid);
int pcmk__lock_pidfile(const char *filename, const char *name);


// bitwise arithmetic utilities

/*!
 * \internal
 * \brief Set specified flags in a flag group
 *
 * \param[in] function    Function name of caller
 * \param[in] line        Line number of caller
 * \param[in] log_level   Log a message at this level
 * \param[in] flag_type   Label describing this flag group (for logging)
 * \param[in] target      Name of object whose flags these are (for logging)
 * \param[in] flag_group  Flag group being manipulated
 * \param[in] flags       Which flags in the group should be set
 * \param[in] flags_str   Readable equivalent of \p flags (for logging)
 *
 * \return Possibly modified flag group
 */
static inline uint64_t
pcmk__set_flags_as(const char *function, int line, uint8_t log_level,
                   const char *flag_type, const char *target,
                   uint64_t flag_group, uint64_t flags, const char *flags_str)
{
    uint64_t result = flag_group | flags;

    if (result != flag_group) {
        do_crm_log_unlikely(log_level,
                            "%s flags %#.8" PRIx64 " (%s) for %s set by %s:%d",
                            pcmk__s(flag_type, "Group of"), flags,
                            pcmk__s(flags_str, "flags"),
                            pcmk__s(target, "target"), function, line);
    }
    return result;
}

/*!
 * \internal
 * \brief Clear specified flags in a flag group
 *
 * \param[in] function    Function name of caller
 * \param[in] line        Line number of caller
 * \param[in] log_level   Log a message at this level
 * \param[in] flag_type   Label describing this flag group (for logging)
 * \param[in] target      Name of object whose flags these are (for logging)
 * \param[in] flag_group  Flag group being manipulated
 * \param[in] flags       Which flags in the group should be cleared
 * \param[in] flags_str   Readable equivalent of \p flags (for logging)
 *
 * \return Possibly modified flag group
 */
static inline uint64_t
pcmk__clear_flags_as(const char *function, int line, uint8_t log_level,
                     const char *flag_type, const char *target,
                     uint64_t flag_group, uint64_t flags, const char *flags_str)
{
    uint64_t result = flag_group & ~flags;

    if (result != flag_group) {
        do_crm_log_unlikely(log_level,
                            "%s flags %#.8" PRIx64
                            " (%s) for %s cleared by %s:%d",
                            pcmk__s(flag_type, "Group of"), flags,
                            pcmk__s(flags_str, "flags"),
                            pcmk__s(target, "target"), function, line);
    }
    return result;
}

/*!
 * \internal
 * \brief Check whether any of specified flags are set in a flag group
 *
 * \param[in] flag_group      Flag group to check whether \p flags_to_check are
 *                            set
 * \param[in] flags_to_check  Flags to check whether set in \p flag_group
 *
 * \retval \c true   if \p flags_to_check is nonzero and any of its flags are
 *                   set in \p flag_group
 * \retval \c false  otherwise
 */
static inline bool
pcmk__any_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) != 0;
}

/*!
 * \internal
 * \brief Check whether all of specified flags are set in a flag group
 *
 * \param[in] flag_group      Flag group to check whether \p flags_to_check are
 *                            set
 * \param[in] flags_to_check  Flags to check whether set in \p flag_group
 *
 * \retval \c true   if all flags in \p flags_to_check are set in \p flag_group
 *                   or if \p flags_to_check is 0
 * \retval \c false  otherwise
 */
static inline bool
pcmk__all_flags_set(uint64_t flag_group, uint64_t flags_to_check)
{
    return (flag_group & flags_to_check) == flags_to_check;
}

/*!
 * \internal
 * \brief Convenience alias for \c pcmk__all_flags_set(), to check single flag
 *
 * This is truly identical to \c pcmk__all_flags_set() but allows a call that's
 * shorter and semantically clearer for checking a single flag.
 *
 * \param[in] flag_group  Flag group (check whether \p flag is set in this)
 * \param[in] flag        Flag (check whether this is set in \p flag_group)
 *
 * \retval \c true   if \p flag is set in \p flag_group or if \p flag is 0
 * \retval \c false  otherwise
 */
static inline bool
pcmk__is_set(uint64_t flag_group, uint64_t flag)
{
    return pcmk__all_flags_set(flag_group, flag);
}

/*!
 * \internal
 * \brief Get readable string for whether specified flags are set
 *
 * \param[in] flag_group    Group of flags to check
 * \param[in] flags         Which flags in \p flag_group should be checked
 *
 * \return "true" if all \p flags are set in \p flag_group, otherwise "false"
 */
static inline const char *
pcmk__flag_text(uint64_t flag_group, uint64_t flags)
{
    return pcmk__btoa(pcmk__all_flags_set(flag_group, flags));
}


// miscellaneous utilities (from utils.c)

int pcmk__compare_versions(const char *version1, const char *version2);
int pcmk__daemon_user(uid_t *uid, gid_t *gid);
void pcmk__daemonize(const char *name, const char *pidfile);
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

/*!
 * \internal
 * \brief Allocate new zero-initialized memory, asserting on failure
 *
 * \param[in] file      File where \p function is located
 * \param[in] function  Calling function
 * \param[in] line      Line within \p file
 * \param[in] nmemb     Number of elements to allocate memory for
 * \param[in] size      Size of each element
 *
 * \return Newly allocated memory of of size <tt>nmemb * size</tt> (guaranteed
 *         not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
static inline void *
pcmk__assert_alloc_as(const char *file, const char *function, uint32_t line,
                      size_t nmemb, size_t size)
{
    void *ptr = calloc(nmemb, size);

    if (ptr == NULL) {
        crm_abort(file, function, line, "Out of memory", FALSE, TRUE);
        crm_exit(CRM_EX_OSERR);
    }
    return ptr;
}

/*!
 * \internal
 * \brief Allocate new zero-initialized memory, asserting on failure
 *
 * \param[in] nmemb  Number of elements to allocate memory for
 * \param[in] size   Size of each element
 *
 * \return Newly allocated memory of of size <tt>nmemb * size</tt> (guaranteed
 *         not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
#define pcmk__assert_alloc(nmemb, size) \
    pcmk__assert_alloc_as(__FILE__, __func__, __LINE__, nmemb, size)

/*!
 * \internal
 * \brief Resize a dynamically allocated memory block
 *
 * \param[in] ptr   Memory block to resize (or NULL to allocate new memory)
 * \param[in] size  New size of memory block in bytes (must be > 0)
 *
 * \return Pointer to resized memory block
 *
 * \note This asserts on error, so the result is guaranteed to be non-NULL
 *       (which is the main advantage of this over directly using realloc()).
 */
static inline void *
pcmk__realloc(void *ptr, size_t size)
{
    void *new_ptr;

    // realloc(p, 0) can replace free(p) but this wrapper can't
    pcmk__assert(size > 0);

    new_ptr = realloc(ptr, size);
    if (new_ptr == NULL) {
        free(ptr);
        abort();
    }
    return new_ptr;
}

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

// internal resource agent functions (from agents.c)
int pcmk__effective_rc(int rc);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_INTERNAL__H
