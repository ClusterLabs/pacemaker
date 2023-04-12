/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_LOGGING_COMPAT__H
#  define PCMK__CRM_COMMON_LOGGING_COMPAT__H

#include <glib.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker logging API
 * \ingroup core
 * \deprecated Do not include this header directly. Do not use Pacemaker
 *             libraries for general-purpose logging; libqb's logging API is a
 *             suitable replacement. The logging APIs in this header, and the
 *             header itself, will be removed in a future release.
 */

//! \deprecated This enum will be removed in a future release
enum xml_log_options {
    xml_log_option_filtered     = 0x0001,
    xml_log_option_formatted    = 0x0002,
    xml_log_option_text         = 0x0004,
    xml_log_option_full_fledged = 0x0008,
    xml_log_option_diff_plus    = 0x0010,
    xml_log_option_diff_minus   = 0x0020,
    xml_log_option_diff_short   = 0x0040,
    xml_log_option_diff_all     = 0x0100,
    xml_log_option_dirty_add    = 0x1000,
    xml_log_option_open         = 0x2000,
    xml_log_option_children     = 0x4000,
    xml_log_option_close        = 0x8000,
};

/*!
 * \brief Log a message using constant priority
 *
 * \param[in] level     Priority at which to log the message
 * \param[in] fmt       printf-style format string literal for message
 * \param[in] args      Any arguments needed by format string
 *
 * \deprecated Do not use Pacemaker for general-purpose logging
 * \note This is a macro, and \p level may be evaluated more than once.
 *       This does nothing when level is LOG_STDOUT.
 */
#  define do_crm_log_always(level, fmt, args...) do {                       \
        switch (level) {                                                    \
            case LOG_STDOUT: case LOG_NEVER:                                \
                break;                                                      \
            default:                                                        \
                qb_log((level), fmt , ##args);                              \
                break;                                                      \
        }                                                                   \
    } while (0)

//! \deprecated Do not use Pacemaker for general-purpose string handling
#define crm_str(x) (const char *) ((x)? (x) : "<null>")

//! \deprecated Do not use Pacemaker for general-purpose logging
gboolean crm_log_cli_init(const char *entity);

//! \deprecated Do not use Pacemaker for general-purpose logging
gboolean crm_add_logfile(const char *filename);

//! \deprecated Do not use Pacemaker for general-purpose logging
void log_data_element(int log_level, const char *file, const char *function,
                      int line, const char *prefix, const xmlNode *data,
                      int depth, int legacy_options);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_LOGGING_COMPAT__H
