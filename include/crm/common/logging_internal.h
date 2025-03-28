/*
 * Copyright 2015-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_LOGGING_INTERNAL__H
#define PCMK__CRM_COMMON_LOGGING_INTERNAL__H

#include <glib.h>

#include <crm/common/internal.h>        // pcmk__is_set()
#include <crm/common/logging.h>
#include <crm/common/output_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Define custom log priorities.
 *
 * syslog(3) uses int for priorities, but libqb's struct qb_log_callsite uses
 * uint8_t, so make sure they fit in the latter.
 */

#ifndef PCMK__LOG_STDOUT
/*!
 * \internal
 * \brief Request to print message to \c stdout instead of logging it
 *
 * Some callees print nothing when this is the log level.
 *
 * \note This value must stay the same as \c LOG_STDOUT until the latter is
 *       dropped. Be mindful of public API functions that may pass arbitrary
 *       integer log levels as well.
 */
#define PCMK__LOG_STDOUT 254
#endif  // PCMK__LOG_STDOUT

/*!
 * \internal
 * \brief Log a message at \c LOG_EMERG level
 *
 * \param[in] fmt   \c printf() format string for log message
 * \param[in] args  Format string arguments
 */
#define pcmk__emerg(fmt, args...) qb_log(LOG_EMERG, fmt, ##args)

/*!
 * \internal
 * \brief Log a message at \c LOG_CRIT level
 *
 * \param[in] fmt   \c printf() format string for log message
 * \param[in] args  Format string arguments
 */
#define pcmk__crit(fmt, args...) qb_log(LOG_CRIT, fmt, ##args)

/*!
 * \internal
 * \brief Log a message at \c LOG_ERR level
 *
 * \param[in] fmt   \c printf() format string for log message
 * \param[in] args  Format string arguments
 */
#define pcmk__err(fmt, args...) qb_log(LOG_ERR, fmt, ##args)

/*!
 * \internal
 * \brief Log a message at \c LOG_WARN level
 *
 * \param[in] fmt   \c printf() format string for log message
 * \param[in] args  Format string arguments
 */
#define pcmk__warn(fmt, args...) qb_log(LOG_WARNING, fmt, ##args)

/*!
 * \internal
 * \brief Log a message at \c LOG_NOTICE level
 *
 * \param[in] fmt   \c printf() format string for log message
 * \param[in] args  Format string arguments
 */
#define pcmk__notice(fmt, args...) qb_log(LOG_NOTICE, fmt, ##args)

/*!
 * \internal
 * \brief Log a message at \c LOG_INFO level
 *
 * \param[in] fmt   \c printf() format string for log message
 * \param[in] args  Format string arguments
 */
#define pcmk__info(fmt, args...) qb_log(LOG_INFO, fmt, ##args)

/*!
 * \internal
 * \brief Log a message at \c LOG_DEBUG level
 *
 * \param[in] fmt   \c printf() format string for log message
 * \param[in] args  Format string arguments
 */
#define pcmk__debug(fmt, args...) do_crm_log_unlikely(LOG_DEBUG, fmt, ##args)

/* Some warnings are too noisy when logged every time a given function is called
 * (for example, using a deprecated feature). As an alternative, we allow
 * warnings to be logged once per invocation of the calling program. Each of
 * those warnings needs a flag defined here.
 */
enum pcmk__warnings {
    pcmk__wo_blind                  = (1 << 0),
    pcmk__wo_record_pending         = (1 << 1),
    pcmk__wo_require_all            = (1 << 4),
    pcmk__wo_order_score            = (1 << 5),
    pcmk__wo_group_order            = (1 << 11),
    pcmk__wo_group_coloc            = (1 << 12),
    pcmk__wo_set_ordering           = (1 << 15),
    pcmk__wo_rdisc_enabled          = (1 << 16),
    pcmk__wo_op_attr_expr           = (1 << 19),
    pcmk__wo_clone_master_max       = (1 << 23),
    pcmk__wo_clone_master_node_max  = (1 << 24),
    pcmk__wo_master_role            = (1 << 26),
    pcmk__wo_slave_role             = (1 << 27),
};

/*!
 * \internal
 * \brief Log a warning once per invocation of calling program
 *
 * \param[in] wo_flag  enum pcmk__warnings value for this warning
 * \param[in] fmt...   printf(3)-style format and arguments
 */
#define pcmk__warn_once(wo_flag, fmt...) do {                           \
        if (!pcmk__is_set(pcmk__warnings, wo_flag)) {                   \
            if (wo_flag == pcmk__wo_blind) {                            \
                pcmk__warn(fmt);                                        \
            } else {                                                    \
                pcmk__config_warn(fmt);                                 \
            }                                                           \
            pcmk__warnings = pcmk__set_flags_as(__func__, __LINE__,     \
                                                LOG_TRACE,              \
                                                "Warn-once", "logging", \
                                                pcmk__warnings,         \
                                                (wo_flag), #wo_flag);   \
        }                                                               \
    } while (0)

typedef void (*pcmk__config_error_func) (void *ctx, const char *msg, ...)
        G_GNUC_PRINTF(2, 3);
typedef void (*pcmk__config_warning_func) (void *ctx, const char *msg, ...)
        G_GNUC_PRINTF(2, 3);

extern pcmk__config_error_func pcmk__config_error_handler;
extern pcmk__config_warning_func pcmk__config_warning_handler;

extern void *pcmk__config_error_context;
extern void *pcmk__config_warning_context;

void pcmk__set_config_error_handler(pcmk__config_error_func error_handler, void *error_context);
void pcmk__set_config_warning_handler(pcmk__config_warning_func warning_handler, void *warning_context);

/* Pacemaker library functions set this when a configuration error is found,
 * which turns on extra messages at the end of processing.
 */
extern bool pcmk__config_has_error;

/* Pacemaker library functions set this when a configuration warning is found,
 * which turns on extra messages at the end of processing.
 */
extern bool pcmk__config_has_warning;

/*!
 * \internal
 * \brief Log an error and make crm_verify return failure status
 *
 * \param[in] fmt...  printf(3)-style format string and arguments
 */
#define pcmk__config_err(fmt...) do {                               \
        pcmk__config_has_error = true;                              \
        if (pcmk__config_error_handler == NULL) {                   \
            pcmk__err(fmt);                                         \
        } else {                                                    \
            pcmk__config_error_handler(pcmk__config_error_context, fmt);   \
        }                                                           \
    } while (0)

/*!
 * \internal
 * \brief Log a warning and make crm_verify return failure status
 *
 * \param[in] fmt...  printf(3)-style format string and arguments
 */
#define pcmk__config_warn(fmt...) do {                                      \
        pcmk__config_has_warning = true;                                    \
        if (pcmk__config_warning_handler == NULL) {                         \
            pcmk__warn(fmt);                                                \
        } else {                                                            \
            pcmk__config_warning_handler(pcmk__config_warning_context, fmt);\
        }                                                                   \
    } while (0)

/*!
 * \internal
 * \brief Execute code depending on whether trace logging is enabled
 *
 * This is similar to \p do_crm_log_unlikely() except instead of logging, it
 * selects one of two code blocks to execute.
 *
 * \param[in] if_action    Code block to execute if trace logging is enabled
 * \param[in] else_action  Code block to execute if trace logging is not enabled
 *
 * \note Neither \p if_action nor \p else_action can contain a \p break or
 *       \p continue statement.
 */
#define pcmk__if_tracing(if_action, else_action) do {                   \
        static struct qb_log_callsite *trace_cs = NULL;                 \
                                                                        \
        if (trace_cs == NULL) {                                         \
            trace_cs = qb_log_callsite_get(__func__, __FILE__,          \
                                           "if_tracing", LOG_TRACE,     \
                                           __LINE__, crm_trace_nonlog); \
        }                                                               \
        if (crm_is_callsite_active(trace_cs, LOG_TRACE,                 \
                                   crm_trace_nonlog)) {                 \
            if_action;                                                  \
        } else {                                                        \
            else_action;                                                \
        }                                                               \
    } while (0)

/*!
 * \internal
 * \brief Log XML changes line-by-line in a formatted fashion
 *
 * \param[in] level  Priority at which to log the messages
 * \param[in] xml    XML to log
 *
 * \note This does nothing when \p level is \c PCMK__LOG_STDOUT.
 */
#define pcmk__log_xml_changes(level, xml) do {                              \
        uint8_t _level = pcmk__clip_log_level(level);                       \
        static struct qb_log_callsite *xml_cs = NULL;                       \
                                                                            \
        switch (_level) {                                                   \
            case PCMK__LOG_STDOUT:                                          \
            case LOG_NEVER:                                                 \
                break;                                                      \
            default:                                                        \
                if (xml_cs == NULL) {                                       \
                    xml_cs = qb_log_callsite_get(__func__, __FILE__,        \
                                                 "xml-changes", _level,     \
                                                 __LINE__, 0);              \
                }                                                           \
                if (crm_is_callsite_active(xml_cs, _level, 0)) {            \
                    pcmk__log_xml_changes_as(__FILE__, __func__, __LINE__,  \
                                             0, _level, xml);               \
                }                                                           \
                break;                                                      \
        }                                                                   \
    } while(0)

/*!
 * \internal
 * \brief Log an XML patchset line-by-line in a formatted fashion
 *
 * \param[in] level     Priority at which to log the messages
 * \param[in] patchset  XML patchset to log
 *
 * \note This does nothing when \p level is \c PCMK__LOG_STDOUT.
 */
#define pcmk__log_xml_patchset(level, patchset) do {                        \
        uint8_t _level = pcmk__clip_log_level(level);                       \
        static struct qb_log_callsite *xml_cs = NULL;                       \
                                                                            \
        switch (_level) {                                                   \
            case PCMK__LOG_STDOUT:                                          \
            case LOG_NEVER:                                                 \
                break;                                                      \
            default:                                                        \
                if (xml_cs == NULL) {                                       \
                    xml_cs = qb_log_callsite_get(__func__, __FILE__,        \
                                                 "xml-patchset", _level,    \
                                                 __LINE__, 0);              \
                }                                                           \
                if (crm_is_callsite_active(xml_cs, _level, 0)) {            \
                    pcmk__log_xml_patchset_as(__FILE__, __func__, __LINE__, \
                                              0, _level, patchset);         \
                }                                                           \
                break;                                                      \
        }                                                                   \
    } while(0)

void pcmk__log_xml_changes_as(const char *file, const char *function,
                              uint32_t line, uint32_t tags, uint8_t level,
                              const xmlNode *xml);

void pcmk__log_xml_patchset_as(const char *file, const char *function,
                               uint32_t line, uint32_t tags, uint8_t level,
                               const xmlNode *patchset);

/*!
 * \internal
 * \brief Initialize logging for command line tools
 *
 * \param[in] name      The name of the program
 * \param[in] verbosity How verbose to be in logging
 *
 * \note \p verbosity is not the same as the logging level (LOG_ERR, etc.).
 */
void pcmk__cli_init_logging(const char *name, unsigned int verbosity);

int pcmk__add_logfile(const char *filename);
void pcmk__add_logfiles(gchar **log_files, pcmk__output_t *out);

void pcmk__free_common_logger(void);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_LOGGING_INTERNAL__H
