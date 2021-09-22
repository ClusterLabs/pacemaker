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

void crm_mon_register_messages(pcmk__output_t *out);

pcmk__output_t *crm_mon_mk_curses_output(char **argv);
void curses_formatted_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);
void curses_formatted_vprintf(pcmk__output_t *out, const char *format, va_list args) G_GNUC_PRINTF(2, 0);
void curses_indented_printf(pcmk__output_t *out, const char *format, ...) G_GNUC_PRINTF(2, 3);
void curses_indented_vprintf(pcmk__output_t *out, const char *format, va_list args) G_GNUC_PRINTF(2, 0);

void blank_screen(void);

#if CURSES_ENABLED
extern GOptionEntry crm_mon_curses_output_entries[];
#define CRM_MON_SUPPORTED_FORMAT_CURSES { "console", crm_mon_mk_curses_output, crm_mon_curses_output_entries }
#endif
