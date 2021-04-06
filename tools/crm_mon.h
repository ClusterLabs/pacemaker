/*
 * Copyright 2019-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <glib.h>

#include <crm/common/output_internal.h>
#include <crm/common/curses_internal.h>
#include <crm/pengine/pe_types.h>
#include <crm/stonith-ng.h>

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

#define mon_show_stack          (1 << 0)
#define mon_show_dc             (1 << 1)
#define mon_show_times          (1 << 2)
#define mon_show_counts         (1 << 3)
#define mon_show_options        (1 << 4)
#define mon_show_nodes          (1 << 5)
#define mon_show_resources      (1 << 6)
#define mon_show_attributes     (1 << 7)
#define mon_show_failcounts     (1 << 8)
#define mon_show_operations     (1 << 9)
#define mon_show_fence_failed   (1 << 10)
#define mon_show_fence_pending  (1 << 11)
#define mon_show_fence_worked   (1 << 12)
#define mon_show_tickets        (1 << 13)
#define mon_show_bans           (1 << 14)
#define mon_show_failures       (1 << 15)

#define mon_show_fencing_all    (mon_show_fence_failed | mon_show_fence_pending | mon_show_fence_worked)
#define mon_show_summary        (mon_show_stack | mon_show_dc | mon_show_times | mon_show_counts)
#define mon_show_all            (mon_show_summary | mon_show_nodes | mon_show_resources | \
                                 mon_show_attributes | mon_show_failcounts | mon_show_operations | \
                                 mon_show_fencing_all | mon_show_tickets | mon_show_bans | \
                                 mon_show_failures | mon_show_options)

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
#define mon_op_cib_native           (0x1000U)

#define mon_op_default              (mon_op_print_pending | mon_op_fence_history | mon_op_fence_connect)

void print_status(pe_working_set_t *data_set, crm_exit_t history_rc,
                  stonith_history_t *stonith_history, unsigned int mon_ops,
                  unsigned int show, char *prefix, char *only_node, char *only_rsc);
void print_xml_status(pe_working_set_t *data_set, crm_exit_t history_rc,
                      stonith_history_t *stonith_history, unsigned int mon_ops,
                      unsigned int show, char *prefix, char *only_node,
                      char *only_rsc);
int print_html_status(pe_working_set_t *data_set, crm_exit_t history_rc,
                      stonith_history_t *stonith_history, unsigned int mon_ops,
                      unsigned int show, char *prefix, char *only_node,
                      char *only_rsc);

void crm_mon_register_messages(pcmk__output_t *out);

pcmk__output_t *crm_mon_mk_curses_output(char **argv);
void curses_formatted_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);
void curses_formatted_vprintf(pcmk__output_t *out, const char *format, va_list args) G_GNUC_PRINTF(2, 0);
void curses_indented_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);
void curses_indented_vprintf(pcmk__output_t *out, const char *format, va_list args) G_GNUC_PRINTF(2, 0);

#if CURSES_ENABLED
extern GOptionEntry crm_mon_curses_output_entries[];
#define CRM_MON_SUPPORTED_FORMAT_CURSES { "console", crm_mon_mk_curses_output, crm_mon_curses_output_entries }
#endif

pcmk__output_t *crm_mon_mk_xml_output(char **argv);
#define CRM_MON_SUPPORTED_FORMAT_XML { "xml", crm_mon_mk_xml_output, pcmk__xml_output_entries }
