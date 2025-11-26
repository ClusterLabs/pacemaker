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

#include <glib.h>               // GHashTable

#include <crm/common/agents_internal.h>
#include <crm/common/acl_internal.h>
#include <crm/common/actions_internal.h>
#include <crm/common/digest_internal.h>
#include <crm/common/failcounts_internal.h>
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

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_INTERNAL__H
