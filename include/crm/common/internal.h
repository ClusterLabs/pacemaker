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

#include <glib.h>               // guint, GHashTable

#include <crm/common/agents_internal.h>
#include <crm/common/acl_internal.h>
#include <crm/common/actions_internal.h>
#include <crm/common/digest_internal.h>
#include <crm/common/flags_internal.h>
#include <crm/common/health_internal.h>
#include <crm/common/io_internal.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/lists_internal.h>
#include <crm/common/mainloop_internal.h>
#include <crm/common/memory_internal.h>
#include <crm/common/messages_internal.h>
#include <crm/common/nvpair_internal.h>
#include <crm/common/pid_internal.h>
#include <crm/common/procfs_internal.h>
#include <crm/common/results_internal.h>
#include <crm/common/scores_internal.h>
#include <crm/common/strings_internal.h>
#include <crm/common/utils_internal.h>

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
