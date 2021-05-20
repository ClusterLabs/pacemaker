/*
 * Copyright 2015-2021 the Pacemaker project contributors
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
#  define PCMK__LOGGING_INTERNAL_H

/*!
 * \internal
 * \brief Log a configuration error
 *
 * \param[in] fmt   printf(3)-style format string
 * \param[in] ...   Arguments for format string
 */
#  define pcmk__config_err(fmt...) do {     \
        crm_config_error = TRUE;            \
        crm_err(fmt);                       \
    } while (0)

/*!
 * \internal
 * \brief Log a configuration warning
 *
 * \param[in] fmt   printf(3)-style format string
 * \param[in] ...   Arguments for format string
 */
#  define pcmk__config_warn(fmt...) do {    \
        crm_config_warning = TRUE;          \
        crm_warn(fmt);                      \
    } while (0)

/*!
 * \internal
 * \brief Execute code depending on whether message would be logged
 *
 * This is similar to do_crm_log_unlikely() except instead of logging, it either
 * continues past this statement or executes else_action depending on whether a
 * message of the given severity would be logged or not. This allows whole
 * blocks of code to be skipped if tracing or debugging is turned off.
 *
 * \param[in] level        Severity at which to continue past this statement
 * \param[in] else_action  Code block to execute if severity would not be logged
 *
 * \note else_action must not contain a break or continue statement
 */
#  define pcmk__log_else(level, else_action) do {                           \
        static struct qb_log_callsite *trace_cs = NULL;                     \
                                                                            \
        if (trace_cs == NULL) {                                             \
            trace_cs = qb_log_callsite_get(__func__, __FILE__, "log_else",  \
                                           level, __LINE__, 0);             \
        }                                                                   \
        if (!crm_is_callsite_active(trace_cs, level, 0)) {                  \
            else_action;                                                    \
        }                                                                   \
    } while(0)

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

#ifdef __cplusplus
}
#endif

#endif
