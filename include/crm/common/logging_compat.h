/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_LOGGING_COMPAT__H
#define PCMK__CRM_COMMON_LOGGING_COMPAT__H

#include <qb/qblog.h>   // qb_log_ctl(), QB_LOG_CONF_EXTENDED

#ifdef __cplusplus
extern "C" {
#endif

//! \deprecated Use qb_log_ctl() directly instead
#define crm_extended_logging(t, e) qb_log_ctl((t), QB_LOG_CONF_EXTENDED, (e))

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_LOGGING_COMPAT__H
