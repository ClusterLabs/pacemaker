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

#include <qb/qblog.h>   // qb_log_ctl(), QB_*

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Deprecated Pacemaker logging API
 * \ingroup core
 * \deprecated Do not include this header directly. The logging APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated use QB_XS instead
#define CRM_XS QB_XS

//! \deprecated Use qb_log_ctl() directly instead
#define crm_extended_logging(t, e) qb_log_ctl((t), QB_LOG_CONF_EXTENDED, (e))

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use Pacemaker for general-purpose logging
#define crm_perror(level, fmt, args...) do {                                \
        uint8_t _level = pcmk__clip_log_level(level);                       \
                                                                            \
        switch (_level) {                                                   \
            case LOG_NEVER:                                                 \
                break;                                                      \
            default: {                                                      \
                const char *err = strerror(errno);                          \
                if (_level <= crm_log_level) {                              \
                    fprintf(stderr, fmt ": %s (%d)\n", ##args, err, errno); \
                }                                                           \
                /* Pass original level arg since do_crm_log() also declares \
                 * _level                                                   \
                 */                                                         \
                do_crm_log((level), fmt ": %s (%d)", ##args, err, errno);   \
            }                                                               \
            break;                                                          \
        }                                                                   \
    } while (0)

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

//! \deprecated Do not use
#define crm_log_xml_err(xml, text) do_crm_log_xml(LOG_ERR, text, xml)

//! \deprecated Do not use
#define crm_log_xml_warn(xml, text) do_crm_log_xml(LOG_WARNING, text, xml)

//! \deprecated Do not use
#define crm_log_xml_notice(xml, text) do_crm_log_xml(LOG_NOTICE, text, xml)

//! \deprecated Do not use
#define crm_log_xml_info(xml, text) do_crm_log_xml(LOG_INFO, text, xml)

//! \deprecated Do not use
#define crm_log_xml_debug(xml, text) do_crm_log_xml(LOG_DEBUG, text, xml)

//! \deprecated Do not use
#define crm_log_xml_trace(xml, text) do_crm_log_xml(LOG_TRACE, text, xml)

#if defined(__clang__)
//! \deprecated Do not use
#define CRM_TRACE_INIT_DATA(name)
#else
#include <assert.h> // required by QB_LOG_INIT_DATA() macro
//! \deprecated Do not use
#define CRM_TRACE_INIT_DATA(name) QB_LOG_INIT_DATA(name)
#endif  // defined(__clang__)

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_LOGGING_COMPAT__H
