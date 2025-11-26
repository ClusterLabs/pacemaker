/*
 * Copyright 2015-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <pid_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_PID_INTERNAL__H
#define PCMK__CRM_COMMON_PID_INTERNAL__H

#include <sys/types.h>                      // pid_t
#include <unistd.h>                         // getpid()

#include <crm/common/strings_internal.h>    // pcmk__assert_asprintf

#ifdef __cplusplus
extern "C" {
#endif

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

static inline char *
pcmk__getpid_s(void)
{
    return pcmk__assert_asprintf("%lu", (unsigned long) getpid());
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_PID_INTERNAL__H
