/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * \file
 * \brief Wrappers for and extensions to libqb logging
 * \ingroup core
 */

#ifndef CRM_LOGGING__H
#  define CRM_LOGGING__H
#  include <qb/qblog.h>
#  ifndef LOG_TRACE
#    define LOG_TRACE    LOG_DEBUG+1
#  endif
#  define LOG_DEBUG_2  LOG_TRACE
#  define LOG_DEBUG_3  LOG_TRACE
#  define LOG_DEBUG_4  LOG_TRACE
#  define LOG_DEBUG_5  LOG_TRACE
#  define LOG_DEBUG_6  LOG_TRACE

extern unsigned int crm_log_level;
extern gboolean crm_config_error;
extern gboolean crm_config_warning;
extern unsigned int crm_trace_nonlog;

enum xml_log_options
{
    xml_log_option_filtered   = 0x0001,
    xml_log_option_formatted  = 0x0002,
    xml_log_option_diff_plus  = 0x0010,
    xml_log_option_diff_minus = 0x0020,
    xml_log_option_diff_short = 0x0040,
    xml_log_option_diff_all   = 0x0100,
    xml_log_option_dirty_add  = 0x1000,
    xml_log_option_open       = 0x2000,
    xml_log_option_children   = 0x4000,
    xml_log_option_close      = 0x8000,
};

void crm_enable_blackbox(int nsig);
void crm_disable_blackbox(int nsig);
void crm_write_blackbox(int nsig, struct qb_log_callsite *callsite);

void crm_update_callsites(void);

void crm_log_deinit(void);

gboolean crm_log_cli_init(const char *entity);

void crm_log_preinit(const char *entity, int argc, char **argv);
gboolean crm_log_init(const char *entity, uint8_t level, gboolean daemon,
                      gboolean to_stderr, int argc, char **argv, gboolean quiet);

void crm_log_args(int argc, char **argv);
void crm_log_output_fn(const char *file, const char *function, int line, int level,
                       const char *prefix, const char *output);
#  define crm_log_output(level, prefix, output) crm_log_output_fn(__FILE__, __FUNCTION__, __LINE__, level, prefix, output)

gboolean crm_add_logfile(const char *filename);

void crm_bump_log_level(int argc, char **argv);

void crm_enable_stderr(int enable);

gboolean crm_is_callsite_active(struct qb_log_callsite *cs, uint8_t level, uint32_t tags);

void log_data_element(int log_level, const char *file, const char *function, int line,
                      const char *prefix, xmlNode * data, int depth, gboolean formatted);

/* returns the old value */
unsigned int set_crm_log_level(unsigned int level);

unsigned int get_crm_log_level(void);

/*
 * Throughout the macros below, note the leading, pre-comma, space in the
 * various ' , ##args' occurences to aid portability across versions of 'gcc'.
 *	http://gcc.gnu.org/onlinedocs/cpp/Variadic-Macros.html#Variadic-Macros
 */
#if defined(__clang__)
#    define CRM_TRACE_INIT_DATA(name)
#  else
#    define CRM_TRACE_INIT_DATA(name) QB_LOG_INIT_DATA(name)
#endif

#  define do_crm_log(level, fmt, args...) qb_log_from_external_source( __func__, __FILE__, fmt, level, __LINE__, 0, ##args)

/* level /MUST/ be a constant or compilation will fail */
#  define do_crm_log_unlikely(level, fmt, args...) do {               \
        static struct qb_log_callsite *trace_cs = NULL;                 \
        if(trace_cs == NULL) {                                          \
            trace_cs = qb_log_callsite_get(__func__, __FILE__, fmt, level, __LINE__, 0); \
        }                                                               \
        if (crm_is_callsite_active(trace_cs, level, 0)) {            \
            qb_log_from_external_source(                                \
                __func__, __FILE__, fmt, level, __LINE__, 0,  ##args);  \
        }                                                               \
    } while(0)

#  define CRM_LOG_ASSERT(expr) do {					\
        if(__unlikely((expr) == FALSE)) {				\
            static struct qb_log_callsite *core_cs = NULL;              \
            if(core_cs == NULL) {                                       \
                core_cs = qb_log_callsite_get(__func__, __FILE__, "log-assert", LOG_TRACE, __LINE__, 0); \
            }                                                           \
            crm_abort(__FILE__, __FUNCTION__, __LINE__, #expr,   \
                      core_cs?core_cs->targets:FALSE, TRUE);            \
        }                                                               \
    } while(0)

/* 'failure_action' MUST NOT be 'continue' as it will apply to the
 * macro's do-while loop
 */
#  define CRM_CHECK(expr, failure_action) do {				\
	if(__unlikely((expr) == FALSE)) {				\
            static struct qb_log_callsite *core_cs = NULL;              \
            if(core_cs == NULL) {                                       \
                core_cs = qb_log_callsite_get(__func__, __FILE__, "check-assert", LOG_TRACE, __LINE__, 0); \
            }                                                           \
	    crm_abort(__FILE__, __FUNCTION__, __LINE__, #expr,	\
		      core_cs?core_cs->targets:FALSE, TRUE);            \
	    failure_action;						\
	}								\
    } while(0)

#  define do_crm_log_xml(level, text, xml) do {                       \
        static struct qb_log_callsite *xml_cs = NULL;                   \
        if(xml_cs == NULL) {                                            \
            xml_cs = qb_log_callsite_get(__func__, __FILE__, "xml-blob", level, __LINE__, 0); \
        }                                                               \
        if (crm_is_callsite_active(xml_cs, level, 0)) {                  \
            log_data_element(level, __FILE__, __FUNCTION__, __LINE__, text, xml, 1, xml_log_option_formatted); \
        }                                                               \
    } while(0)

#  define do_crm_log_alias(level, file, function, line, fmt, args...) do { \
        if(level > 0) {                                                 \
            qb_log_from_external_source(function, file, fmt, level, line, 0,  ##args); \
        } else {                                                        \
            printf(fmt "\n", ##args);                                    \
        }                                                               \
    } while(0)

#  define do_crm_log_always(level, fmt, args...) qb_log(level, "%s: " fmt, __FUNCTION__ , ##args)

#  define crm_perror(level, fmt, args...) do {				\
	const char *err = strerror(errno);				\
	fprintf(stderr, fmt ": %s (%d)\n", ##args, err, errno);		\
	do_crm_log(level, fmt ": %s (%d)", ##args, err, errno);		\
    } while(0)

#  define crm_log_tag(level, tag, fmt, args...)    do {               \
        static struct qb_log_callsite *trace_tag_cs = NULL;                 \
        int converted_tag = g_quark_try_string(tag);                   \
        if(trace_tag_cs == NULL) {                                          \
            trace_tag_cs = qb_log_callsite_get(__func__, __FILE__, fmt, level, __LINE__, converted_tag); \
        }                                                               \
        if (crm_is_callsite_active(trace_tag_cs, level, converted_tag)) {               \
            qb_log_from_external_source( __func__, __FILE__, fmt, level, __LINE__, converted_tag, ##args); \
        }                                                               \
      } while(0)

#  define crm_crit(fmt, args...)    qb_logt(LOG_CRIT,    0, fmt , ##args)
#  define crm_err(fmt, args...)     qb_logt(LOG_ERR,     0, fmt , ##args)
#  define crm_warn(fmt, args...)    qb_logt(LOG_WARNING, 0, fmt , ##args)
#  define crm_notice(fmt, args...)  qb_logt(LOG_NOTICE,  0, fmt , ##args)
#  define crm_info(fmt, args...)    qb_logt(LOG_INFO,    0, fmt , ##args)

#  define crm_debug(fmt, args...)   do_crm_log_unlikely(LOG_DEBUG, fmt , ##args)
#  define crm_trace(fmt, args...)   do_crm_log_unlikely(LOG_TRACE, fmt , ##args)

#  define crm_log_xml_crit(xml, text)    do_crm_log_xml(LOG_CRIT,    text, xml)
#  define crm_log_xml_err(xml, text)     do_crm_log_xml(LOG_ERR,     text, xml)
#  define crm_log_xml_warn(xml, text)    do_crm_log_xml(LOG_WARNING, text, xml)
#  define crm_log_xml_notice(xml, text)  do_crm_log_xml(LOG_NOTICE,  text, xml)
#  define crm_log_xml_info(xml, text)    do_crm_log_xml(LOG_INFO,    text, xml)
#  define crm_log_xml_debug(xml, text)   do_crm_log_xml(LOG_DEBUG,   text, xml)
#  define crm_log_xml_trace(xml, text)   do_crm_log_xml(LOG_TRACE,   text, xml)

#  define crm_log_xml_explicit(xml, text)  do {                 \
        static struct qb_log_callsite *digest_cs = NULL;        \
        digest_cs = qb_log_callsite_get(                        \
            __func__, __FILE__, text, LOG_TRACE, __LINE__,      \
            crm_trace_nonlog);                                  \
        if (digest_cs && digest_cs->targets) {                  \
            do_crm_log_xml(LOG_TRACE,   text, xml);             \
        }                                                       \
    } while(0)

#  define crm_str(x)    (const char*)(x?x:"<null>")

#endif
