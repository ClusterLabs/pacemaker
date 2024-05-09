/*
 * Copyright 2015-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PCMK__LOGGING_INTERNAL_H
#define PCMK__LOGGING_INTERNAL_H

#include <glib.h>

#include <crm/common/logging.h>
#include <crm/common/output_internal.h>

/* Some warnings are too noisy when logged every time a given function is called
 * (for example, using a deprecated feature). As an alternative, we allow
 * warnings to be logged once per invocation of the calling program. Each of
 * those warnings needs a flag defined here.
 */
enum pcmk__warnings {
    pcmk__wo_blind          = (1 << 0),
    pcmk__wo_restart_type   = (1 << 1),
    pcmk__wo_role_after     = (1 << 2),
    pcmk__wo_poweroff       = (1 << 3),
    pcmk__wo_require_all    = (1 << 4),
    pcmk__wo_order_score    = (1 << 5),
    pcmk__wo_neg_threshold  = (1 << 6),
    pcmk__wo_remove_after   = (1 << 7),
    pcmk__wo_ping_node      = (1 << 8),
    pcmk__wo_order_inst     = (1 << 9),
    pcmk__wo_coloc_inst     = (1 << 10),
    pcmk__wo_group_order    = (1 << 11),
    pcmk__wo_group_coloc    = (1 << 12),
    pcmk__wo_upstart        = (1 << 13),
    pcmk__wo_nagios         = (1 << 14),
    pcmk__wo_set_ordering   = (1 << 15),
    pcmk__wo_rdisc_enabled  = (1 << 16),
    pcmk__wo_rkt            = (1 << 17),
    pcmk__wo_location_rules = (1 << 18),
    pcmk__wo_op_attr_expr   = (1 << 19),
    pcmk__wo_instance_defaults  = (1 << 20),
    pcmk__wo_multiple_rules     = (1 << 21),
    pcmk__wo_master_element = (1 << 22),
    pcmk__wo_clone_master_max       = (1 << 23),
    pcmk__wo_clone_master_node_max  = (1 << 24),
    pcmk__wo_bundle_master  = (1 << 25),
    pcmk__wo_master_role    = (1 << 26),
    pcmk__wo_slave_role     = (1 << 27),
};

/*!
 * \internal
 * \brief Log a warning once per invocation of calling program
 *
 * \param[in] wo_flag  enum pcmk__warnings value for this warning
 * \param[in] fmt...   printf(3)-style format and arguments
 */
#define pcmk__warn_once(wo_flag, fmt...) do {                           \
        if (!pcmk_is_set(pcmk__warnings, wo_flag)) {                    \
            if (wo_flag == pcmk__wo_blind) {                            \
                crm_warn(fmt);                                          \
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

typedef void (*pcmk__config_error_func) (void *ctx, const char *msg, ...);
typedef void (*pcmk__config_warning_func) (void *ctx, const char *msg, ...);

extern pcmk__config_error_func pcmk__config_error_handler;
extern pcmk__config_warning_func pcmk__config_warning_handler;

extern void *pcmk__config_error_context;
extern void *pcmk__config_warning_context;

void pcmk__set_config_error_handler(pcmk__config_error_func error_handler, void *error_context);
void pcmk__set_config_warning_handler(pcmk__config_warning_func warning_handler, void *warning_context);

/*!
 * \internal
 * \brief Log an error and make crm_verify return failure status
 *
 * \param[in] fmt...  printf(3)-style format string and arguments
 */
#define pcmk__config_err(fmt...) do {                               \
        crm_config_error = TRUE;                                    \
        if (pcmk__config_error_handler == NULL) {                   \
            crm_err(fmt);                                           \
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
        crm_config_warning = TRUE;                                          \
        if (pcmk__config_warning_handler == NULL) {                         \
            crm_warn(fmt);                                                  \
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
 * \note This does nothing when \p level is \c LOG_STDOUT.
 */
#define pcmk__log_xml_changes(level, xml) do {                              \
        uint8_t _level = pcmk__clip_log_level(level);                       \
        static struct qb_log_callsite *xml_cs = NULL;                       \
                                                                            \
        switch (_level) {                                                   \
            case LOG_STDOUT:                                                \
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
 * \note This does nothing when \p level is \c LOG_STDOUT.
 */
#define pcmk__log_xml_patchset(level, patchset) do {                        \
        uint8_t _level = pcmk__clip_log_level(level);                       \
        static struct qb_log_callsite *xml_cs = NULL;                       \
                                                                            \
        switch (_level) {                                                   \
            case LOG_STDOUT:                                                \
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

#endif
