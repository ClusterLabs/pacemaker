/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_FAILCOUNTS_INTERNAL__H
#define PCMK__CRM_COMMON_FAILCOUNTS_INTERNAL__H

#include <stdint.h>                         // UINT32_C

#include <glib.h>                           // guint

#include <crm/common/logging.h>             // CRM_CHECK
#include <crm/common/strings_internal.h>    // pcmk__assert_asprintf

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Options when getting resource fail counts
 */
enum pcmk__fc_flags {
    pcmk__fc_default   = (UINT32_C(1) << 0),

    //! Don't count expired failures
    pcmk__fc_effective = (UINT32_C(1) << 1),

    //! If resource is a launcher, include failures of launched resources
    pcmk__fc_launched  = (UINT32_C(1) << 2),
};

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

#endif // PCMK__CRM_COMMON_FAILCOUNTS_INTERNAL__H
