/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PENGINE_PRINT_ML_STATUS__H
#  define PENGINE_PRINT_ML_STATUS__H

#ifdef __cplusplus
extern "C" {
#endif
    
#  include <stdint.h>
#  include <crm/pengine/status.h>
#  include <crm/stonith-ng.h>

/*
 * Definitions indicating which items to print
 */

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

/*
 * Definitions indicating how to output
 */

enum mon_output_format_e {
    mon_output_none,
    mon_output_monitor,
    mon_output_plain,
    mon_output_console,
    mon_output_xml,
    mon_output_html,
    mon_output_cgi
} output_format = mon_output_console;

struct print_params_t
{
    unsigned int show;
    gboolean group_by_node;
    gboolean inactive_resources;
    gboolean print_timing;
    gboolean fence_history;
    gboolean fence_full_history;
    gboolean print_brief;
    gboolean print_pending;
    gboolean print_clone_detail;
    /* FIXME allow, detect, and correctly interpret glob pattern or regex? */
    const char *print_neg_location_prefix;
};

#if CURSES_ENABLED
#  define print_dot() if (output_format == mon_output_console) { \
        printw(".");                            \
        clrtoeol();                             \
        refresh();                              \
    } else {                                    \
        fprintf(stdout, ".");                   \
    }
#else
#  define print_dot() fprintf(stdout, ".");
#endif

#if CURSES_ENABLED
#  define print_as(fmt, args...) if (output_format == mon_output_console) { \
        printw(fmt, ##args);                            \
        clrtoeol();                                     \
        refresh();                                      \
    } else {                                            \
        fprintf(stdout, fmt, ##args);                   \
    }
#else
#  define print_as(fmt, args...) fprintf(stdout, fmt, ##args);
#endif

int get_resource_display_options(void);
void print_cluster_summary(FILE *stream, pe_working_set_t *data_set);
void print_resources(FILE *stream, pe_working_set_t *data_set, int print_opts);
void print_node_attributes(FILE *stream, pe_working_set_t *data_set);
void print_node_summary(FILE *stream, pe_working_set_t * data_set, gboolean operations);
void print_failed_actions(FILE *stream, pe_working_set_t *data_set);
void print_stonith_history(FILE *stream, stonith_history_t *history);
void print_stonith_action(FILE *stream, stonith_history_t *event);
void print_cluster_tickets(FILE *stream, pe_working_set_t * data_set);
void print_neg_locations(FILE *stream, pe_working_set_t *data_set);
void print_xml_status(FILE *stream, pe_working_set_t * data_set,  stonith_history_t *stonith_history
                      , struct print_params_t print_params);

#ifdef __cplusplus
}
#endif

#endif
