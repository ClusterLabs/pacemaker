/*
 * Copyright 2015-2021 the Pacemaker project contributors
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
#include <stdint.h>             // uint8_t, uint64_t
#include <string.h>             // strcmp()
#include <fcntl.h>              // open()
#include <sys/types.h>          // uid_t, gid_t, pid_t

#include <glib.h>               // guint, GList, GHashTable
#include <libxml/tree.h>        // xmlNode

#include <crm/common/util.h>    // crm_strdup_printf()
#include <crm/common/logging.h>  // do_crm_log_unlikely(), etc.
#include <crm/common/mainloop.h> // mainloop_io_t, struct ipc_client_callbacks
#include <crm/common/iso8601_internal.h>
#include <crm/common/results_internal.h>
#include <crm/common/strings_internal.h>

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

/* internal ACL-related utilities */

char *pcmk__uid2username(uid_t uid);
const char *pcmk__update_acl_user(xmlNode *request, const char *field,
                                  const char *peer_user);

static inline bool
pcmk__is_privileged(const char *user)
{
    return user && (!strcmp(user, CRM_DAEMON_USER) || !strcmp(user, "root"));
}

void pcmk__unpack_acl(xmlNode *source, xmlNode *target, const char *user);

bool pcmk__check_acl(xmlNode *xml, const char *name,
                     enum xml_private_flags mode);

void pcmk__apply_acl(xmlNode *xml);

#if SUPPORT_CIBSECRETS
/* internal CIB utilities (from cib_secrets.c) */

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
char *pcmk__full_path(const char *filename, const char *dirname);
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


/* internal main loop utilities (from mainloop.c) */

int pcmk__add_mainloop_ipc(crm_ipc_t *ipc, int priority, void *userdata,
                           struct ipc_client_callbacks *callbacks,
                           mainloop_io_t **source);
guint pcmk__mainloop_timer_get_period(mainloop_timer_t *timer);


/* internal messaging utilities (from messages.c) */

const char *pcmk__message_name(const char *name);


/* internal name/value utilities (from nvpair.c) */

int pcmk__scan_nvpair(const char *input, char **name, char **value);
char *pcmk__format_nvpair(const char *name, const char *value,
                          const char *units);
char *pcmk__format_named_time(const char *name, time_t epoch_time);

/*!
 * \internal
 * \brief Add a boolean attribute to an XML node.
 *
 * \param[in,out] node  XML node to add attributes to
 * \param[in]     name  XML attribute to create
 * \param[in]     value Value to give to the attribute
 */
void
pcmk__xe_set_bool_attr(xmlNodePtr node, const char *name, bool value);

/*!
 * \internal
 * \brief Extract a boolean attribute's value from an XML element
 *
 * \param[in] node XML node to get attribute from
 * \param[in] name XML attribute to get
 *
 * \return True if the given \p name is an attribute on \p node and has
 *         the value "true", False in all other cases
 */
bool
pcmk__xe_attr_is_true(xmlNodePtr node, const char *name);

/*!
 * \internal
 * \brief Extract a boolean attribute's value from an XML element, with
 *        error checking
 *
 * \param[in]  node  XML node to get attribute from
 * \param[in]  name  XML attribute to get
 * \param[out] value Destination for the value of the attribute
 *
 * \return EINVAL if \p name or \p value are NULL, ENODATA if \p node is
 *         NULL or the attribute does not exist, pcmk_rc_unknown_format
 *         if the attribute is not a boolean, and pcmk_rc_ok otherwise.
 *
 * \note \p value only has any meaning if the return value is pcmk_rc_ok.
 */
int
pcmk__xe_get_bool_attr(xmlNodePtr node, const char *name, bool *value);


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


/* internal functions related to resource operations (from operations.c) */

// printf-style format to create operation ID from resource, action, interval
#define PCMK__OP_FMT "%s_%s_%u"

char *pcmk__op_key(const char *rsc_id, const char *op_type, guint interval_ms);
char *pcmk__notify_key(const char *rsc_id, const char *notify_type,
                       const char *op_type);
char *pcmk__transition_key(int transition_id, int action_id, int target_rc,
                           const char *node);
void pcmk__filter_op_for_digest(xmlNode *param_set);


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
                            "%s flags 0x%.8llx (%s) for %s set by %s:%d",
                            ((flag_type == NULL)? "Group of" : flag_type),
                            (unsigned long long) flags,
                            ((flags_str == NULL)? "flags" : flags_str),
                            ((target == NULL)? "target" : target),
                            function, line);
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
                            "%s flags 0x%.8llx (%s) for %s cleared by %s:%d",
                            ((flag_type == NULL)? "Group of" : flag_type),
                            (unsigned long long) flags,
                            ((flags_str == NULL)? "flags" : flags_str),
                            ((target == NULL)? "target" : target),
                            function, line);
    }
    return result;
}

// miscellaneous utilities (from utils.c)

void pcmk__daemonize(const char *name, const char *pidfile);
void pcmk__panic(const char *origin);
pid_t pcmk__locate_sbd(void);
void pcmk__sleep_ms(unsigned int ms);

extern int pcmk__score_red;
extern int pcmk__score_green;
extern int pcmk__score_yellow;

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
    CRM_ASSERT(size > 0);

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

// internal resource agent functions (from agents.c)
int pcmk__effective_rc(int rc);

#endif /* CRM_COMMON_INTERNAL__H */
