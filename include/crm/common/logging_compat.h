/*
 * Copyright 2024-2025 the Pacemaker project contributors
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

//! \deprecated use QB_XS instead
#define CRM_XS QB_XS

//! \deprecated Use qb_log_ctl() directly instead
#define crm_extended_logging(t, e) qb_log_ctl((t), QB_LOG_CONF_EXTENDED, (e))

//! \deprecated Do not use
#define crm_emerg(fmt, args...) qb_log(LOG_EMERG, fmt, ##args)

//! \deprecated Do not use
#define crm_crit(fmt, args...) qb_log(LOG_CRIT, fmt, ##args)

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define crm_err(fmt, args...) qb_log(LOG_ERR, fmt, ##args)

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define crm_warn(fmt, args...) qb_log(LOG_WARNING, fmt, ##args)

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define crm_notice(fmt, args...) qb_log(LOG_NOTICE, fmt, ##args)

//! \deprecated Do not use
#define crm_info(fmt, args...) qb_log(LOG_INFO, fmt, ##args)

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define crm_debug(fmt, args...) do_crm_log_unlikely(LOG_DEBUG, fmt, ##args)

//! \deprecated Do not use
#define crm_trace(fmt, args...) do_crm_log_unlikely(LOG_TRACE, fmt, ##args)

//! \deprecated Do not use
#define crm_log_xml_crit(xml, text) do_crm_log_xml(LOG_CRIT, text, xml)

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_LOGGING_COMPAT__H
