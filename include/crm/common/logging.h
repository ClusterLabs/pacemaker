/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_LOGGING__H
#define PCMK__CRM_COMMON_LOGGING__H

#include <stdio.h>
#include <stdint.h>             // uint8_t, uint32_t
#include <glib.h>
#include <qb/qblog.h>           // LOG_TRACE, qb_*
#include <libxml/tree.h>

#include <crm/common/results.h>     // crm_abort

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Wrappers for and extensions to libqb logging
 * \ingroup core
 */


/* Define custom log priorities.
 *
 * syslog(3) uses int for priorities, but libqb's struct qb_log_callsite uses
 * uint8_t, so make sure they fit in the latter.
 */

// Print message to stdout instead of logging it
#ifndef LOG_STDOUT
#define LOG_STDOUT  254
#endif

// Don't send message anywhere
#ifndef LOG_NEVER
#define LOG_NEVER   255
#endif

// @COMPAT Make internal when we can break API backward compatibility
//! \deprecated Do not use
extern unsigned int crm_log_level;

// @COMPAT Make internal when we can break API backward compatibility
//! \deprecated Do not use
extern unsigned int crm_trace_nonlog;

void crm_enable_blackbox(int nsig);
void crm_disable_blackbox(int nsig);
void crm_write_blackbox(int nsig, const struct qb_log_callsite *callsite);

void crm_update_callsites(void);

void crm_log_deinit(void);

/*!
 * \brief Initializes the logging system and defaults to the least verbose output level
 *
 * \param[in] entity  If not NULL, will be used as the identity for logging purposes
 * \param[in] argc    The number of command line parameters
 * \param[in] argv    The command line parameter values
 */
void crm_log_preinit(const char *entity, int argc, char *const *argv);
gboolean crm_log_init(const char *entity, uint8_t level, gboolean daemon,
                      gboolean to_stderr, int argc, char **argv, gboolean quiet);

void crm_log_args(int argc, char **argv);
void crm_log_output_fn(const char *file, const char *function, int line, int level,
                       const char *prefix, const char *output);

// Log a block of text line by line
#define crm_log_output(level, prefix, output)   \
    crm_log_output_fn(__FILE__, __func__, __LINE__, level, prefix, output)

void crm_bump_log_level(int argc, char **argv);

void crm_enable_stderr(int enable);

gboolean crm_is_callsite_active(struct qb_log_callsite *cs, uint8_t level, uint32_t tags);

// NOTE: sbd (as of at least 1.5.2) uses this
/* returns the old value */
unsigned int set_crm_log_level(unsigned int level);

unsigned int get_crm_log_level(void);

void pcmk_log_xml_as(const char *file, const char *function, uint32_t line,
                     uint32_t tags, uint8_t level, const char *text,
                     const xmlNode *xml);

/*!
 * \internal
 * \brief Clip log_level to \p uint8_t range
 *
 * \param[in] level  Log level to clip
 *
 * \return 0 if \p level is less than 0, \p UINT8_MAX if \p level is greater
 *         than \p UINT8_MAX, or \p level otherwise
 */
/* @COMPAT: Make this function internal at a compatibility break. It's used in
 * public macros for now.
 */
static inline uint8_t
pcmk__clip_log_level(int level)
{
    if (level <= 0) {
        return 0;
    }
    if (level >= UINT8_MAX) {
        return UINT8_MAX;
    }
    return level;
}

/* Using "switch" instead of "if" in these macro definitions keeps
 * static analysis from complaining about constant evaluations
 */

/*!
 * \brief Log a message
 *
 * \param[in] level  Priority at which to log the message
 * \param[in] fmt    printf-style format string literal for message
 * \param[in] args   Any arguments needed by format string
 */
#define do_crm_log(level, fmt, args...) \
        do_crm_log_alias(level, __FILE__, __func__, __LINE__, fmt, ##args)

/*!
 * \brief Log a message that is likely to be filtered out
 *
 * \param[in] level  Priority at which to log the message
 * \param[in] fmt    printf-style format string for message
 * \param[in] args   Any arguments needed by format string
 *
 * \note This does nothing when level is \p LOG_STDOUT.
 */
#define do_crm_log_unlikely(level, fmt, args...) do {                       \
        uint8_t _level = pcmk__clip_log_level(level);                       \
                                                                            \
        switch (_level) {                                                   \
            case LOG_STDOUT: case LOG_NEVER:                                \
                break;                                                      \
            default: {                                                      \
                static struct qb_log_callsite *trace_cs = NULL;             \
                if (trace_cs == NULL) {                                     \
                    trace_cs = qb_log_callsite_get(__func__, __FILE__, fmt, \
                                                   _level, __LINE__, 0);    \
                }                                                           \
                if (crm_is_callsite_active(trace_cs, _level, 0)) {          \
                    qb_log_from_external_source(__func__, __FILE__, fmt,    \
                                                _level, __LINE__, 0,        \
                                                ##args);                    \
                }                                                           \
            }                                                               \
            break;                                                          \
        }                                                                   \
    } while (0)

#define CRM_LOG_ASSERT(expr) do {                                       \
        if (!(expr)) {                                                  \
            static struct qb_log_callsite *core_cs = NULL;              \
            if(core_cs == NULL) {                                       \
                core_cs = qb_log_callsite_get(__func__, __FILE__,       \
                                              "log-assert", LOG_TRACE,  \
                                              __LINE__, 0);             \
            }                                                           \
            crm_abort(__FILE__, __func__, __LINE__, #expr,              \
                      core_cs?core_cs->targets:FALSE, TRUE);            \
        }                                                               \
    } while(0)

// NOTE: sbd (as of at least 1.5.2) uses this
/* 'failure_action' MUST NOT be 'continue' as it will apply to the
 * macro's do-while loop
 */
#define CRM_CHECK(expr, failure_action) do {                            \
        if (!(expr)) {                                                  \
            static struct qb_log_callsite *core_cs = NULL;              \
            if (core_cs == NULL) {                                      \
                core_cs = qb_log_callsite_get(__func__, __FILE__,       \
                                              "check-assert",           \
                                              LOG_TRACE, __LINE__, 0);  \
            }                                                           \
            crm_abort(__FILE__, __func__, __LINE__, #expr,              \
                (core_cs? core_cs->targets: FALSE), TRUE);              \
            failure_action;                                             \
        }                                                               \
    } while(0)

/*!
 * \brief Log XML line-by-line in a formatted fashion
 *
 * \param[in] level  Priority at which to log the messages
 * \param[in] text   Prefix for each line
 * \param[in] xml    XML to log
 *
 * \note This does nothing when \p level is \p LOG_STDOUT.
 */
#define do_crm_log_xml(level, text, xml) do {                           \
        uint8_t _level = pcmk__clip_log_level(level);                   \
        static struct qb_log_callsite *xml_cs = NULL;                   \
                                                                        \
        switch (_level) {                                               \
            case LOG_STDOUT:                                            \
            case LOG_NEVER:                                             \
                break;                                                  \
            default:                                                    \
                if (xml_cs == NULL) {                                   \
                    xml_cs = qb_log_callsite_get(__func__, __FILE__,    \
                                                 "xml-blob", _level,    \
                                                 __LINE__, 0);          \
                }                                                       \
                if (crm_is_callsite_active(xml_cs, _level, 0)) {        \
                    pcmk_log_xml_as(__FILE__, __func__, __LINE__, 0,    \
                                    _level, text, (xml));               \
                }                                                       \
                break;                                                  \
        }                                                               \
    } while(0)

/*!
 * \brief Log a message as if it came from a different code location
 *
 * \param[in] level     Priority at which to log the message
 * \param[in] file      Source file name to use instead of __FILE__
 * \param[in] function  Source function name to use instead of __func__
 * \param[in] line      Source line number to use instead of __line__
 * \param[in] fmt       printf-style format string literal for message
 * \param[in] args      Any arguments needed by format string
 */
#define do_crm_log_alias(level, file, function, line, fmt, args...) do {    \
        uint8_t _level = pcmk__clip_log_level(level);                       \
                                                                            \
        switch (_level) {                                                   \
            case LOG_STDOUT:                                                \
                printf(fmt "\n", ##args);                                   \
                break;                                                      \
            case LOG_NEVER:                                                 \
                break;                                                      \
            default:                                                        \
                qb_log_from_external_source(function, file, fmt, _level,    \
                                            line, 0, ##args);               \
                break;                                                      \
        }                                                                   \
    } while (0)

/*!
 * \brief Log a message with a tag (for use with PCMK_trace_tags)
 *
 * \param[in] level  Priority at which to log the message
 * \param[in] tag    String to tag message with
 * \param[in] fmt    printf-style format string for message
 * \param[in] args   Any arguments needed by format string
 *
 * \note This does nothing when level is LOG_STDOUT.
 */
#define crm_log_tag(level, tag, fmt, args...) do {                          \
        uint8_t _level = pcmk__clip_log_level(level);                       \
                                                                            \
        switch (_level) {                                                   \
            case LOG_STDOUT: case LOG_NEVER:                                \
                break;                                                      \
            default: {                                                      \
                static struct qb_log_callsite *trace_tag_cs = NULL;         \
                int converted_tag = g_quark_try_string(tag);                \
                if (trace_tag_cs == NULL) {                                 \
                    trace_tag_cs = qb_log_callsite_get(__func__, __FILE__,  \
                                                       fmt, _level,         \
                                                       __LINE__,            \
                                                       converted_tag);      \
                }                                                           \
                if (crm_is_callsite_active(trace_tag_cs, _level,            \
                                           converted_tag)) {                \
                    qb_log_from_external_source(__func__, __FILE__, fmt,    \
                                                _level, __LINE__,           \
                                                converted_tag, ##args);     \
                }                                                           \
            }                                                               \
        }                                                                   \
    } while (0)

#define crm_log_xml_explicit(xml, text)  do {                   \
        static struct qb_log_callsite *digest_cs = NULL;        \
        digest_cs = qb_log_callsite_get(                        \
            __func__, __FILE__, text, LOG_TRACE, __LINE__,      \
            crm_trace_nonlog);                                  \
        if (digest_cs && digest_cs->targets) {                  \
            do_crm_log_xml(LOG_TRACE,   text, xml);             \
        }                                                       \
    } while(0)

#ifdef __cplusplus
}
#endif

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
#include <crm/common/logging_compat.h>
#endif

#endif
