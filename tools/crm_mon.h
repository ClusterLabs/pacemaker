/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <glib.h>

#include <crm/common/output.h>
#include <crm/common/curses_internal.h>
#include <crm/pengine/pe_types.h>
#include <crm/stonith-ng.h>

/* Never display node attributes whose name starts with one of these prefixes */
#define FILTER_STR { CRM_FAIL_COUNT_PREFIX, CRM_LAST_FAILURE_PREFIX,       \
                     "shutdown", "terminate", "standby", "probe_complete", \
                     "#", NULL }

/* Convenience macro for prettifying output (e.g. "node" vs "nodes") */
#define s_if_plural(i) (((i) == 1)? "" : "s")

#if CURSES_ENABLED
#  define print_dot(output_format) if (output_format == mon_output_console) { \
	printw(".");				\
	clrtoeol();				\
	refresh();				\
    } else {					\
	fprintf(stdout, ".");			\
    }
#else
#  define print_dot(output_format) fprintf(stdout, ".");
#endif

#if CURSES_ENABLED
#  define print_as(output_format, fmt, args...) if (output_format == mon_output_console) { \
	printw(fmt, ##args);				\
	clrtoeol();					\
	refresh();					\
    } else {						\
	fprintf(stdout, fmt, ##args);			\
    }
#else
#  define print_as(output_format, fmt, args...) fprintf(stdout, fmt, ##args);
#endif

typedef enum mon_output_format_e {
    mon_output_unset,
    mon_output_none,
    mon_output_monitor,
    mon_output_plain,
    mon_output_console,
    mon_output_xml,
    mon_output_legacy_xml,
    mon_output_html,
    mon_output_cgi
} mon_output_format_t;

#define mon_show_times         (0x0001U)
#define mon_show_stack         (0x0002U)
#define mon_show_dc            (0x0004U)
#define mon_show_count         (0x0008U)
#define mon_show_nodes         (0x0010U)
#define mon_show_resources     (0x0020U)
#define mon_show_attributes    (0x0040U)
#define mon_show_failcounts    (0x0080U)
#define mon_show_operations    (0x0100U)
#define mon_show_tickets       (0x0200U)
#define mon_show_bans          (0x0400U)
#define mon_show_fence_history (0x0800U)

#define mon_show_headers       (mon_show_times | mon_show_stack | mon_show_dc \
                               | mon_show_count)
#define mon_show_default       (mon_show_headers | mon_show_nodes \
                               | mon_show_resources)
#define mon_show_all           (mon_show_default | mon_show_attributes \
                               | mon_show_failcounts | mon_show_operations \
                               | mon_show_tickets | mon_show_bans \
                               | mon_show_fence_history)

#define mon_op_group_by_node        (0x0001U)
#define mon_op_inactive_resources   (0x0002U)
#define mon_op_one_shot             (0x0004U)
#define mon_op_has_warnings         (0x0008U)
#define mon_op_print_timing         (0x0010U)
#define mon_op_watch_fencing        (0x0020U)
#define mon_op_fence_history        (0x0040U)
#define mon_op_fence_full_history   (0x0080U)
#define mon_op_fence_connect        (0x0100U)
#define mon_op_print_brief          (0x0200U)
#define mon_op_print_pending        (0x0400U)
#define mon_op_print_clone_detail   (0x0800U)

#define mon_op_default              (mon_op_print_pending)

void print_status(pcmk__output_t *out, mon_output_format_t output_format,
                  pe_working_set_t *data_set, stonith_history_t *stonith_history,
                  unsigned int mon_ops, unsigned int show, const char *prefix);
void print_xml_status(pcmk__output_t *out, mon_output_format_t output_format,
                      pe_working_set_t *data_set, stonith_history_t *stonith_history,
                      unsigned int mon_ops, unsigned int show, const char *prefix);
int print_html_status(pcmk__output_t *out, mon_output_format_t output_format,
                      pe_working_set_t *data_set, stonith_history_t *stonith_history,
                      unsigned int mon_ops, unsigned int show, const char *prefix);

GList *append_attr_list(GList *attr_list, char *name);
void blank_screen(void);
void crm_mon_get_parameters(resource_t *rsc, pe_working_set_t *data_set);
const char *get_cluster_stack(pe_working_set_t *data_set);
int get_resource_display_options(unsigned int mon_ops,
                                 mon_output_format_t output_format);

void crm_mon_register_messages(pcmk__output_t *out);

pcmk__output_t *crm_mon_mk_curses_output(char **argv);
void curses_indented_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);
void curses_indented_vprintf(pcmk__output_t *out, const char *format, va_list args) G_GNUC_PRINTF(2, 0);

#if CURSES_ENABLED
extern GOptionEntry crm_mon_curses_output_entries[];
#define CRM_MON_SUPPORTED_FORMAT_CURSES { "console", crm_mon_mk_curses_output, crm_mon_curses_output_entries }
#endif

pcmk__output_t *crm_mon_mk_xml_output(char **argv);
#define CRM_MON_SUPPORTED_FORMAT_XML { "xml", crm_mon_mk_xml_output, pcmk__xml_output_entries }
